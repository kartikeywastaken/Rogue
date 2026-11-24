package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rogue/internal/tui"
)

func configEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"ROGUE_PROVIDER", "ROGUE_MODEL", "ROGUE_MODELS", "ROGUE_BASE_URL", "ROGUE_SCOPE", "ROGUE_EXCLUDED", "ROGUE_ALLOWED_TOOLS", "ROGUE_PREAPPROVED_TOOLS", "ROGUE_TIMEOUT", "ROGUE_MAX_ITERATIONS", "ROGUE_MAX_TOOL_CALLS", "ROGUE_MAX_TOKENS", "OPENROUTER_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY", "ANTHROPIC_API_KEY", "ROGUE_FALLBACK_MODELS", "ROGUE_MAX_OUTPUT_TOKENS", "ROGUE_MODEL_RETRIES", "ROGUE_COST_LIMIT_USD", "ROGUE_INPUT_USD_PER_MILLION", "ROGUE_OUTPUT_USD_PER_MILLION", "ROGUE_RETENTION_DAYS", "ROGUE_KEEP_MISSIONS", "ROGUE_STATE_DIR"} {
		t.Setenv(name, "")
	}
	t.Setenv("ROGUE_STATE_DIR", t.TempDir())
	t.Setenv("ROGUE_CREDENTIALS_FILE", "off") // never read the developer's real saved keys
}
func TestMissingKeyDoesNotSelectSimulation(t *testing.T) {
	configEnv(t)
	if _, err := buildEngine(); err == nil || !strings.Contains(err.Error(), "OPENROUTER_API_KEY") {
		t.Fatal("missing key did not fail startup", err)
	}
	t.Setenv("ROGUE_PROVIDER", "mock")
	if _, err := buildEngine(); err == nil {
		t.Fatal("production simulation accepted")
	}
}
func TestLocalConfigurationAndValidation(t *testing.T) {
	configEnv(t)
	t.Setenv("ROGUE_PROVIDER", "ollama")
	t.Setenv("ROGUE_MODEL", "fixture")
	t.Setenv("ROGUE_MODELS", "second,fixture")
	t.Setenv("ROGUE_SCOPE", "localhost,127.0.0.1")
	eng, err := buildEngine()
	if err != nil {
		t.Fatal(err)
	}
	if got := eng.Models(); len(got) != 2 || got[0] != "fixture" {
		t.Fatal(got)
	}
	for _, tc := range []struct{ name, value string }{{"ROGUE_TIMEOUT", "-1s"}, {"ROGUE_MAX_ITERATIONS", "0"}, {"ROGUE_PREAPPROVED_TOOLS", "unknown"}} {
		t.Setenv(tc.name, tc.value)
		if _, err := buildEngine(); err == nil {
			t.Fatal("invalid setting accepted", tc.name)
		}
		t.Setenv(tc.name, "")
	}
}

func TestConnectProviderSavesOnlyWhenAsked(t *testing.T) {
	configEnv(t)
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("ROGUE_CREDENTIALS_FILE", path)

	// Session-only: works, writes nothing.
	eng, err := connectProvider(tui.Credentials{Provider: "openai", APIKey: "sk-session-key-0001", Model: "m1"})
	if err != nil || eng == nil || eng.Models()[0] != "m1" {
		t.Fatal(eng, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("session-only key was written to disk")
	}
	// Missing key is a config error and returns a true nil engine.
	if eng, err := connectProvider(tui.Credentials{Provider: "openai", Model: "m1"}); err == nil || eng != nil {
		t.Fatal("connected without a key", eng)
	}
	// Remember: saved, and the next startup picks it up with no env vars.
	if _, err := connectProvider(tui.Credentials{Provider: "openai", APIKey: "sk-saved-key-0002", Model: "m2", Remember: true}); err != nil {
		t.Fatal(err)
	}
	backend, err := buildEngine()
	if err != nil || backend.Models()[0] != "m2" {
		t.Fatal("saved credentials not used at startup", err)
	}
	// Blank key = keep the saved one.
	if _, err := connectProvider(tui.Credentials{Provider: "openai", Model: "m3", Remember: true}); err != nil {
		t.Fatal(err)
	}
	opts := setupOptions()
	if opts.Provider != "openai" || opts.Model != "m3" || opts.Providers[2].Existing != "saved sk-…0002" {
		t.Fatalf("%+v", opts)
	}
	// An environment key is never copied to disk.
	t.Setenv("GROQ_API_KEY", "gsk-from-env-0003")
	if _, err := connectProvider(tui.Credentials{Provider: "groq", Model: "g", Remember: true}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "gsk-from-env") {
		t.Fatal("environment key persisted")
	}
}
