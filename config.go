package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/engine"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/storage"
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
	config, err := llm.LoadConfig(os.Getenv)
	if err != nil {
		return nil, err
	}
	return buildHarness(config.Client(), config.Models, config.Model)
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
