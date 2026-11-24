package llm

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ProviderInfo describes a supported provider: where it lives and which
// environment variable carries its credential (empty for keyless local servers).
type ProviderInfo struct {
	Name, Label, BaseURL, KeyEnv string
	ModelHint                    string // where to find a model id; ids are never hardcoded defaults
}

// Providers is the single list of supported backends, in display order.
var Providers = []ProviderInfo{
	{Name: "openrouter", Label: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1", KeyEnv: "OPENROUTER_API_KEY", ModelHint: "vendor/model id as listed at openrouter.ai/models"},
	{Name: "anthropic", Label: "Anthropic", BaseURL: "https://api.anthropic.com/v1", KeyEnv: "ANTHROPIC_API_KEY", ModelHint: "model id from docs.anthropic.com, e.g. claude-sonnet-5-5"},
	{Name: "openai", Label: "OpenAI", BaseURL: "https://api.openai.com/v1", KeyEnv: "OPENAI_API_KEY", ModelHint: "a tool-capable model id from platform.openai.com/docs/models"},
	{Name: "groq", Label: "Groq", BaseURL: "https://api.groq.com/openai/v1", KeyEnv: "GROQ_API_KEY", ModelHint: "a tool-capable model id from console.groq.com/docs/models"},
	{Name: "ollama", Label: "Ollama (local, no key)", BaseURL: "http://localhost:11434/v1", ModelHint: "a pulled model with tool support (see `ollama list`)"},
}

// LookupProvider finds a provider by name.
func LookupProvider(name string) (ProviderInfo, bool) {
	for _, p := range Providers {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderInfo{}, false
}

type Config struct {
	Provider, Model, BaseURL, APIKey string
	Models                           []string
	Fallbacks                        []string
	OutputLimit                      int
	Retries                          int
}

// LoadConfig reads explicit configuration. A missing credential never selects a
// simulation. Model IDs are configured instead of maintaining stale defaults.
func LoadConfig(getenv func(string) string) (Config, error) {
	config := Config{Provider: strings.ToLower(strings.TrimSpace(getenv("ROGUE_PROVIDER"))), Model: strings.TrimSpace(getenv("ROGUE_MODEL"))}
	if config.Provider == "" {
		config.Provider = "openrouter"
	}
	if config.Provider == "local" {
		config.Provider = "ollama"
	}
	info, ok := LookupProvider(config.Provider)
	if !ok {
		return config, fmt.Errorf("unsupported ROGUE_PROVIDER %q (use openrouter, openai, groq, anthropic, or ollama)", config.Provider)
	}
	config.BaseURL = info.BaseURL
	keyEnv := info.KeyEnv
	if keyEnv != "" {
		config.APIKey = getenv(keyEnv)
		if strings.TrimSpace(config.APIKey) == "" {
			return config, fmt.Errorf("%s is required for %s", keyEnv, config.Provider)
		}
	}
	if config.Model == "" {
		return config, fmt.Errorf("ROGUE_MODEL is required: choose a tool-capable %s model", config.Provider)
	}
	if base := strings.TrimSpace(getenv("ROGUE_BASE_URL")); base != "" {
		config.BaseURL = strings.TrimRight(base, "/")
	}
	u, err := url.Parse(config.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" {
		return config, fmt.Errorf("ROGUE_BASE_URL must be an HTTP(S) API base URL")
	}
	if config.Provider != "ollama" && u.Scheme != "https" {
		return config, fmt.Errorf("hosted provider credentials require an HTTPS base URL")
	}
	config.Models = []string{config.Model}
	config.OutputLimit = 2048
	config.Retries = 2
	for _, setting := range []struct {
		name     string
		value    *int
		min, max int
	}{{"ROGUE_MAX_OUTPUT_TOKENS", &config.OutputLimit, 64, 32768}, {"ROGUE_MODEL_RETRIES", &config.Retries, 0, 3}} {
		if raw := getenv(setting.name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < setting.min || value > setting.max {
				return config, fmt.Errorf("%s must be between %d and %d", setting.name, setting.min, setting.max)
			}
			*setting.value = value
		}
	}
	for _, model := range strings.Split(getenv("ROGUE_MODELS"), ",") {
		model = strings.TrimSpace(model)
		if model != "" && !slices.Contains(config.Models, model) {
			config.Models = append(config.Models, model)
		}
	}
	for _, model := range strings.Split(getenv("ROGUE_FALLBACK_MODELS"), ",") {
		model = strings.TrimSpace(model)
		if model != "" && !slices.Contains(config.Fallbacks, model) {
			config.Fallbacks = append(config.Fallbacks, model)
			if !slices.Contains(config.Models, model) {
				config.Models = append(config.Models, model)
			}
		}
	}
	return config, nil
}
func (config Config) RawClient() Provider {
	var provider Provider
	if config.Provider == "anthropic" {
		provider = &Anthropic{APIKey: config.APIKey, Endpoint: strings.TrimRight(config.BaseURL, "/") + "/messages", Client: &http.Client{Timeout: 90 * time.Second}, MaxOutputTokens: config.OutputLimit, Retries: config.Retries}
	} else {
		provider = &Client{Name: config.Provider, APIKey: config.APIKey, Endpoint: strings.TrimRight(config.BaseURL, "/") + "/chat/completions", Client: &http.Client{Timeout: 90 * time.Second}, MaxOutputTokens: config.OutputLimit, Retries: config.Retries}
	}
	return provider
}

func (config Config) Client() Provider {
	provider := config.RawClient()
	if len(config.Fallbacks) > 0 {
		return &Fallback{Provider: provider, Models: append([]string(nil), config.Fallbacks...)}
	}
	return provider
}
