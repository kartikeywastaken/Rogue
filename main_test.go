package main

import (
	"strings"
	"testing"
)

func configEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"ROGUE_PROVIDER", "ROGUE_MODEL", "ROGUE_MODELS", "ROGUE_BASE_URL", "ROGUE_SCOPE", "ROGUE_EXCLUDED", "ROGUE_ALLOWED_TOOLS", "ROGUE_PREAPPROVED_TOOLS", "ROGUE_TIMEOUT", "ROGUE_MAX_ITERATIONS", "ROGUE_MAX_TOOL_CALLS", "ROGUE_MAX_TOKENS", "OPENROUTER_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY", "ANTHROPIC_API_KEY", "ROGUE_FALLBACK_MODELS", "ROGUE_MAX_OUTPUT_TOKENS", "ROGUE_MODEL_RETRIES", "ROGUE_COST_LIMIT_USD", "ROGUE_INPUT_USD_PER_MILLION", "ROGUE_OUTPUT_USD_PER_MILLION", "ROGUE_RETENTION_DAYS", "ROGUE_KEEP_MISSIONS", "ROGUE_STATE_DIR"} {
		t.Setenv(name, "")
	}
	t.Setenv("ROGUE_STATE_DIR", t.TempDir())
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
