package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/credentials"
	"rogue/internal/engine"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/plugin"
	"rogue/internal/storage"
	"rogue/internal/telemetry"
	"rogue/internal/tui"
)

// Process-level metrics collector and plugin registry.
// These are shared across all mission execution paths in this process.
var (
	Metrics = telemetry.NewCollector()
	Plugins = plugin.NewRegistry()
)

func newRegistry() *arsenal.Registry {
	registry := arsenal.New()
	arsenal.RegisterReconTools(registry)
	arsenal.RegisterAssessmentTools(registry)
	arsenal.RegisterWebAssessmentTools(registry)
	arsenal.RegisterMissionTools(registry)
	arsenal.RegisterIntelligenceTools(registry)
	arsenal.RegisterExternalTools(registry, arsenal.ExternalOptions{NmapPath: os.Getenv("ROGUE_NMAP_PATH"), CurlPath: os.Getenv("ROGUE_CURL_PATH"), DigPath: os.Getenv("ROGUE_DIG_PATH")})
	arsenal.RegisterCVETool(registry, &arsenal.CVEClient{APIKey: os.Getenv("NVD_API_KEY")})
	arsenal.RegisterResearchTools(registry)
	return registry
}

func loadOptions() (engine.Options, error) {
	rules := mission.Rules{
		Scope: csv(os.Getenv("ROGUE_SCOPE")), Excluded: csv(os.Getenv("ROGUE_EXCLUDED")),
		AllowedTools: csv(os.Getenv("ROGUE_ALLOWED_TOOLS")), PreapprovedTools: csv(os.Getenv("ROGUE_PREAPPROVED_TOOLS")),
	}
	for _, raw := range csv(os.Getenv("ROGUE_ALLOWED_PORTS")) {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return engine.Options{}, fmt.Errorf("ROGUE_ALLOWED_PORTS must contain numeric ports")
		}
		rules.AllowedPorts = append(rules.AllowedPorts, port)
	}
	if err := rules.Validate(); err != nil {
		return engine.Options{}, err
	}
	options := engine.Options{Rules: rules, Timeout: 3 * time.Minute, MaxIterations: 15, MaxToolCalls: 64, MaxTokens: 50000}
	if raw := os.Getenv("ROGUE_LAB"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return options, fmt.Errorf("ROGUE_LAB must be true or false")
		}
		options.Lab = value
	}
	for _, setting := range []struct {
		name  string
		value *int
	}{{"ROGUE_OPSEC_PAUSE_AFTER", &options.OPSEC.PauseAfter}, {"ROGUE_OPSEC_ABORT_AFTER", &options.OPSEC.AbortAfter}} {
		if raw := os.Getenv(setting.name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 0 {
				return options, fmt.Errorf("%s must be nonnegative", setting.name)
			}
			*setting.value = value
		}
	}
	options.Concurrency = 2
	if raw := os.Getenv("ROGUE_CONTEXT_BYTES"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 4096 || value > 128*1024 {
			return options, fmt.Errorf("ROGUE_CONTEXT_BYTES must be between 4096 and 131072")
		}
		options.ContextBytes = value
	}
	if raw := os.Getenv("ROGUE_CONCURRENCY"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 8 {
			return options, fmt.Errorf("ROGUE_CONCURRENCY must be between 1 and 8")
		}
		options.Concurrency = value
	}
	if raw := os.Getenv("ROGUE_COOLDOWN"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value < 0 || value > time.Minute {
			return options, fmt.Errorf("ROGUE_COOLDOWN must be between 0s and 1m")
		}
		options.Cooldown = value
	}
	if value := os.Getenv("ROGUE_TIMEOUT"); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			return options, fmt.Errorf("ROGUE_TIMEOUT must be a positive duration")
		}
		options.Timeout = timeout
	}
	for _, setting := range []struct {
		name  string
		value *int
	}{
		{"ROGUE_MAX_ITERATIONS", &options.MaxIterations}, {"ROGUE_MAX_TOOL_CALLS", &options.MaxToolCalls}, {"ROGUE_MAX_TOKENS", &options.MaxTokens},
	} {
		if raw := os.Getenv(setting.name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 {
				return options, fmt.Errorf("%s must be a positive integer", setting.name)
			}
			*setting.value = value
		}
	}
	for _, setting := range []struct {
		name  string
		value *float64
	}{
		{"ROGUE_COST_LIMIT_USD", &options.CostLimit}, {"ROGUE_INPUT_USD_PER_MILLION", &options.InputPrice}, {"ROGUE_OUTPUT_USD_PER_MILLION", &options.OutputPrice},
	} {
		if raw := os.Getenv(setting.name); raw != "" {
			value, err := strconv.ParseFloat(raw, 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
				return options, fmt.Errorf("%s must be a finite nonnegative number", setting.name)
			}
			*setting.value = value
		}
	}
	if _, err := llm.NewBudget(llm.BudgetLimits{Tokens: options.MaxTokens, Dollars: options.CostLimit, InputPerMillion: options.InputPrice, OutputPerMillion: options.OutputPrice}); err != nil {
		return options, err
	}
	return options, nil
}

func openStore() (*storage.Store, error) {
	directory := os.Getenv("ROGUE_STATE_DIR")
	if directory == "" {
		directory = ".rogue"
	}
	return storage.Open(directory)
}

func buildEngine() (engine.Engine, error) {
	config, err := loadProviderConfig()
	if err != nil {
		return nil, err
	}
	// Return an untyped nil on failure: a nil *Harness inside a non-nil
	// engine.Engine interface would pass an `eng == nil` check.
	harness, err := buildHarness(config.Client(), config.Models, config.Model)
	if err != nil {
		return nil, err
	}
	return harness, nil
}

// keyEnv maps a provider name to the variable holding its API key.
func keyEnv(provider string) string {
	info, _ := llm.LookupProvider(provider)
	return info.KeyEnv
}

// loadProviderConfig reads provider settings from the environment, falling
// back to credentials saved from the TUI for anything the environment leaves
// unset.
func loadProviderConfig() (llm.Config, error) {
	path, pathErr := credentials.Path(os.Getenv)
	saved, loadErr := credentials.Load(path)
	config, err := llm.LoadConfig(saved.Getenv(os.Getenv, keyEnv))
	if err != nil {
		// Only surface credential-file problems when they actually matter.
		return config, errors.Join(err, pathErr, loadErr)
	}
	return config, nil
}

// setupOptions snapshots what is configured for the TUI setup screen. Key
// values never leave this process; the screen only sees a masked hint.
func setupOptions() tui.SetupOptions {
	opts := tui.SetupOptions{}
	path, err := credentials.Path(os.Getenv)
	if err != nil {
		opts.Warning = "cannot locate a config directory, keys will not be saved: " + err.Error()
	}
	opts.SavePath = path
	saved, err := credentials.Load(path)
	if err != nil {
		opts.Warning = err.Error()
	}
	opts.Provider = strings.ToLower(strings.TrimSpace(os.Getenv("ROGUE_PROVIDER")))
	opts.Model = strings.TrimSpace(os.Getenv("ROGUE_MODEL"))
	if opts.Provider == "" {
		opts.Provider = saved.Provider
	}
	if opts.Model == "" && opts.Provider == saved.Provider {
		opts.Model = saved.Model
	}
	opts.BaseURL = strings.TrimSpace(os.Getenv("ROGUE_BASE_URL"))
	if opts.BaseURL == "" && saved.Provider == llm.CustomProvider {
		opts.BaseURL = saved.BaseURL
	}
	for _, p := range llm.Providers {
		choice := tui.ProviderChoice{Name: p.Name, Label: p.Label, KeyEnv: p.KeyEnv, ModelHint: p.ModelHint, KeyOptional: p.KeyOptional, NeedsURL: p.NeedsBaseURL}
		if key := saved.Key(p.Name); key != "" {
			choice.Existing = "saved " + credentials.Mask(key)
		} else if p.KeyEnv != "" && strings.TrimSpace(os.Getenv(p.KeyEnv)) != "" {
			choice.Existing = "from $" + p.KeyEnv
		}
		opts.Providers = append(opts.Providers, choice)
	}
	return opts
}

// currentCredentials describes a startup engine to the TUI so /model can load
// the provider's catalog and switch models. It never includes the key: the
// switch resolves it again from the saved file or the environment. Remember is
// set when the model came from the saved file, so a switch updates that default.
func currentCredentials(config llm.Config) tui.Credentials {
	c := tui.Credentials{Provider: config.Provider, Model: config.Model}
	if info, _ := llm.LookupProvider(config.Provider); info.NeedsBaseURL {
		c.BaseURL = config.BaseURL
	}
	path, _ := credentials.Path(os.Getenv)
	saved, err := credentials.Load(path)
	c.Remember = err == nil && path != "" && saved.Provider == config.Provider &&
		strings.TrimSpace(os.Getenv("ROGUE_MODEL")) == ""
	return c
}

// setupRequest is what the TUI's entries resolve to. Connecting and listing
// models share it so both obey identical key and endpoint rules.
type setupRequest struct {
	info    llm.ProviderInfo
	path    string
	pathErr error
	saved   credentials.File
	loadErr error
	key     string // typed, else saved; an environment key stays in the env
	getenv  func(string) string
}

func resolveSetup(c tui.Credentials) (setupRequest, error) {
	info, ok := llm.LookupProvider(c.Provider)
	if !ok {
		return setupRequest{}, fmt.Errorf("unsupported provider %q", c.Provider)
	}
	r := setupRequest{info: info}
	r.path, r.pathErr = credentials.Path(os.Getenv)
	r.saved, r.loadErr = credentials.Load(r.path)
	r.key = strings.TrimSpace(c.APIKey)
	if r.key == "" && r.loadErr == nil {
		r.key = r.saved.Key(c.Provider) // "keep saved key"; env is the next fallback
	}
	values := map[string]string{"ROGUE_PROVIDER": c.Provider, "ROGUE_MODEL": c.Model}
	if info.NeedsBaseURL {
		values["ROGUE_BASE_URL"] = c.BaseURL
	}
	if info.KeyEnv != "" {
		values[info.KeyEnv] = r.key
	}
	r.getenv = credentials.Override(values, os.Getenv)
	return r, nil
}

// listModels is the TUI's ListModels callback: the provider's catalog for the
// entered key. It costs no tokens. Failure is fine; the user types the id.
func listModels(c tui.Credentials) ([]string, error) {
	r, err := resolveSetup(c)
	if err != nil {
		return nil, err
	}
	config, err := llm.LoadEndpoint(r.getenv)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return llm.ListModels(ctx, config, nil)
}

// connectProvider is the TUI's Connect callback. It validates the entered
// settings through the same llm.LoadConfig path as environment variables,
// builds a harness, and only then (if asked) persists the key.
func connectProvider(c tui.Credentials) (engine.Engine, error) {
	r, err := resolveSetup(c)
	if err != nil {
		return nil, err
	}
	if r.pathErr != nil && c.Remember {
		return nil, r.pathErr
	}
	config, err := llm.LoadConfig(r.getenv)
	if err != nil {
		return nil, err
	}
	harness, err := buildHarness(config.Client(), config.Models, config.Model)
	if err != nil {
		return nil, err
	}
	if c.Remember {
		if r.loadErr != nil {
			return harness, fmt.Errorf("connected, but not saved: %w", r.loadErr)
		}
		// Only a key typed or already saved is written: a key that came from
		// the environment is never silently copied to disk.
		next := r.saved.WithKey(c.Provider, c.Model, r.key)
		if r.info.NeedsBaseURL {
			next = next.WithBaseURL(config.BaseURL)
		}
		if err := credentials.Save(r.path, next); err != nil {
			return harness, fmt.Errorf("connected, but not saved: %w", err)
		}
	}
	return harness, nil
}

func buildHarness(provider llm.Provider, models []string, model string) (*engine.Harness, error) {
	options, err := loadOptions()
	if err != nil {
		return nil, err
	}
	registry := newRegistry()
	for _, names := range [][]string{options.Rules.AllowedTools, options.Rules.PreapprovedTools} {
		for _, name := range names {
			if registry.Get(name) == nil {
				return nil, fmt.Errorf("unknown configured tool %q", name)
			}
		}
	}
	store, err := openStore()
	if err != nil {
		return nil, err
	}
	recovered, err := store.Recover()
	if err != nil {
		return nil, err
	}
	if recovered > 0 {
		fmt.Fprintf(os.Stderr, "rogue: recovered %d interrupted missions; no tool actions were replayed\n", recovered)
	}
	days, keep := 30, 100
	for _, setting := range []struct {
		name  string
		value *int
	}{{"ROGUE_RETENTION_DAYS", &days}, {"ROGUE_KEEP_MISSIONS", &keep}} {
		if raw := os.Getenv(setting.name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > 10000 {
				return nil, fmt.Errorf("%s must be between 1 and 10000", setting.name)
			}
			*setting.value = value
		}
	}
	if _, err := store.Prune(time.Duration(days)*24*time.Hour, keep); err != nil {
		return nil, err
	}
	options.Store = store
	return engine.NewHarnessWithOptions(provider, registry, models, model, options), nil
}

func csv(raw string) []string {
	var values []string
	for _, part := range strings.Split(raw, ",") {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}
