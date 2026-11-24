package llm

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ProviderInfo describes a supported provider: where it lives and which
// environment variable carries its credential (empty for keyless local servers).
// Every provider except anthropic speaks the OpenAI Chat Completions protocol
// (streaming + function calling), which is the only thing Client implements.
type ProviderInfo struct {
	Name, Label, BaseURL, KeyEnv string
	ModelHint                    string // where to find a model id; ids are never hardcoded defaults
	Local                        bool   // runs on this machine: plain HTTP allowed, no key
	KeyOptional                  bool   // a key is sent only if one is configured
	NeedsBaseURL                 bool   // no default endpoint; ROGUE_BASE_URL is required
	// Lenient tolerates tool-call stream quirks of compatibility layers whose
	// exact streaming shape is undocumented (see Client.Lenient).
	Lenient bool
}

// CustomProvider is any other OpenAI-compatible endpoint (vLLM, LiteLLM,
// a gateway, a provider not listed here).
const CustomProvider = "custom"

// Providers is the single list of supported backends, in display order.
var Providers = []ProviderInfo{
	{Name: "openrouter", Label: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1", KeyEnv: "OPENROUTER_API_KEY", ModelHint: "vendor/model id as listed at openrouter.ai/models"},
	{Name: "anthropic", Label: "Anthropic", BaseURL: "https://api.anthropic.com/v1", KeyEnv: "ANTHROPIC_API_KEY", ModelHint: "model id from docs.anthropic.com, e.g. claude-sonnet-5-5"},
	{Name: "openai", Label: "OpenAI", BaseURL: "https://api.openai.com/v1", KeyEnv: "OPENAI_API_KEY", ModelHint: "a tool-capable model id from platform.openai.com/docs/models"},
	{Name: "gemini", Label: "Google Gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai", KeyEnv: "GEMINI_API_KEY", Lenient: true, ModelHint: "a Gemini model id from ai.google.dev/gemini-api/docs/models (key from aistudio.google.com)"},
	{Name: "mistral", Label: "Mistral", BaseURL: "https://api.mistral.ai/v1", KeyEnv: "MISTRAL_API_KEY", ModelHint: "a tool-capable model id from docs.mistral.ai"},
	{Name: "deepseek", Label: "DeepSeek", BaseURL: "https://api.deepseek.com/v1", KeyEnv: "DEEPSEEK_API_KEY", ModelHint: "a model id from api-docs.deepseek.com"},
	{Name: "xai", Label: "xAI (Grok)", BaseURL: "https://api.x.ai/v1", KeyEnv: "XAI_API_KEY", ModelHint: "a model id from docs.x.ai"},
	{Name: "groq", Label: "Groq", BaseURL: "https://api.groq.com/openai/v1", KeyEnv: "GROQ_API_KEY", ModelHint: "a tool-capable model id from console.groq.com/docs/models"},
	{Name: "together", Label: "Together AI", BaseURL: "https://api.together.xyz/v1", KeyEnv: "TOGETHER_API_KEY", ModelHint: "a function-calling model id from docs.together.ai"},
	{Name: "fireworks", Label: "Fireworks AI", BaseURL: "https://api.fireworks.ai/inference/v1", KeyEnv: "FIREWORKS_API_KEY", ModelHint: "accounts/fireworks/models/… id from fireworks.ai/models"},
	{Name: "cerebras", Label: "Cerebras", BaseURL: "https://api.cerebras.ai/v1", KeyEnv: "CEREBRAS_API_KEY", ModelHint: "a tool-capable model id from inference-docs.cerebras.ai"},
	// Gateway to many upstream models; the streamed tool-call shape is undocumented.
	{Name: "experientiallabs", Label: "Experiential Labs", BaseURL: "https://api.experientiallabs.ai/v1", KeyEnv: "EXPLABS_API_KEY", Lenient: true, ModelHint: "a tool-capable model slug from your Experiential Labs catalog (keys start with xpl_)"},
	// Model Studio keys are region-bound, so each region is its own provider and key.
	{Name: "alibaba", Label: "Alibaba Cloud (intl)", BaseURL: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", KeyEnv: "DASHSCOPE_API_KEY", Lenient: true, ModelHint: "a Qwen model id from Model Studio (Singapore region key)"},
	{Name: "alibaba-cn", Label: "Alibaba Cloud (China)", BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", KeyEnv: "DASHSCOPE_CN_API_KEY", Lenient: true, ModelHint: "a Qwen model id from Model Studio (Beijing region key)"},
	{Name: "ollama", Label: "Ollama (local, no key)", BaseURL: "http://localhost:11434/v1", Local: true, ModelHint: "a pulled model with tool support (see `ollama list`)"},
	{Name: "lmstudio", Label: "LM Studio (local, no key)", BaseURL: "http://localhost:1234/v1", Local: true, Lenient: true, ModelHint: "the id of a loaded model with tool support"},
	{Name: CustomProvider, Label: "Other OpenAI-compatible", KeyEnv: "ROGUE_CUSTOM_API_KEY", KeyOptional: true, NeedsBaseURL: true, Lenient: true, ModelHint: "the model id your endpoint expects"},
}

// providerAliases maps alternative spellings to canonical names.
var providerAliases = map[string]string{"local": "ollama", "google": "gemini", "grok": "xai", "lm-studio": "lmstudio", "openai-compatible": CustomProvider,
	"explabs": "experientiallabs", "experiential": "experientiallabs", "dashscope": "alibaba", "qwen": "alibaba", "aliyun": "alibaba-cn"}

// KeyEnvs lists every provider credential variable, for redaction.
func KeyEnvs() []string {
	var names []string
	for _, p := range Providers {
		if p.KeyEnv != "" {
			names = append(names, p.KeyEnv)
		}
	}
	return names
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
	config, err := LoadEndpoint(getenv)
	if err != nil {
		return config, err
	}
	config.Model = strings.TrimSpace(getenv("ROGUE_MODEL"))
	if config.Model == "" {
		return config, fmt.Errorf("ROGUE_MODEL is required: choose a tool-capable %s model", config.Provider)
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

// LoadEndpoint validates everything needed to talk to a provider (name, key,
// base URL, transport rules) without requiring a model. Model listing uses it
// so a catalog request obeys exactly the same rules as chat requests.
func LoadEndpoint(getenv func(string) string) (Config, error) {
	config := Config{Provider: strings.ToLower(strings.TrimSpace(getenv("ROGUE_PROVIDER")))}
	if config.Provider == "" {
		config.Provider = "openrouter"
	}
	if alias, ok := providerAliases[config.Provider]; ok {
		config.Provider = alias
	}
	info, ok := LookupProvider(config.Provider)
	if !ok {
		names := make([]string, len(Providers))
		for i, p := range Providers {
			names[i] = p.Name
		}
		return config, fmt.Errorf("unsupported ROGUE_PROVIDER %q (use one of: %s)", config.Provider, strings.Join(names, ", "))
	}
	config.BaseURL = info.BaseURL
	if info.KeyEnv != "" {
		config.APIKey = strings.TrimSpace(getenv(info.KeyEnv))
		if config.APIKey == "" && !info.KeyOptional {
			return config, fmt.Errorf("%s is required for %s", info.KeyEnv, config.Provider)
		}
	}
	if base := strings.TrimSpace(getenv("ROGUE_BASE_URL")); base != "" {
		config.BaseURL = strings.TrimRight(base, "/")
	} else if info.NeedsBaseURL {
		return config, fmt.Errorf("ROGUE_BASE_URL is required for %s: the endpoint's OpenAI-compatible base, e.g. https://host/v1", config.Provider)
	}
	u, err := url.Parse(config.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" {
		return config, fmt.Errorf("ROGUE_BASE_URL must be an HTTP(S) API base URL")
	}
	if u.Scheme != "https" {
		// Known hosted APIs are always HTTPS. Otherwise a key may only travel
		// in cleartext over loopback, where nobody on the network can sniff it.
		if !info.Local && !info.NeedsBaseURL {
			return config, fmt.Errorf("hosted provider credentials require an HTTPS base URL")
		}
		if config.APIKey != "" && !isLoopback(u.Hostname()) {
			return config, fmt.Errorf("refusing to send an API key over plain HTTP to %s; use HTTPS", u.Hostname())
		}
	}
	return config, nil
}
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (config Config) RawClient() Provider {
	var provider Provider
	if config.Provider == "anthropic" {
		provider = &Anthropic{APIKey: config.APIKey, Endpoint: strings.TrimRight(config.BaseURL, "/") + "/messages", Client: &http.Client{Timeout: 90 * time.Second}, MaxOutputTokens: config.OutputLimit, Retries: config.Retries}
	} else {
		info, _ := LookupProvider(config.Provider)
		provider = &Client{Name: config.Provider, APIKey: config.APIKey, Endpoint: strings.TrimRight(config.BaseURL, "/") + "/chat/completions", Client: &http.Client{Timeout: 90 * time.Second}, MaxOutputTokens: config.OutputLimit, Retries: config.Retries, Lenient: info.Lenient}
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
