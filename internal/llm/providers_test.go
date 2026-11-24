package llm

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestEveryProviderLoads(t *testing.T) {
	for _, p := range Providers {
		t.Run(p.Name, func(t *testing.T) {
			env := map[string]string{"ROGUE_PROVIDER": p.Name, "ROGUE_MODEL": "fixture"}
			if p.KeyEnv != "" {
				env[p.KeyEnv] = "key-123"
			}
			if p.NeedsBaseURL {
				env["ROGUE_BASE_URL"] = "https://gateway.example/v1"
			}
			c, err := LoadConfig(func(k string) string { return env[k] })
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := c.RawClient().(*Client); ok == (p.Name == "anthropic") {
				t.Fatal("wrong protocol client")
			}
			if !p.Local && !strings.HasPrefix(c.BaseURL, "https://") {
				t.Fatal("hosted provider without HTTPS", c.BaseURL)
			}
		})
	}
	if seen := map[string]bool{}; true {
		for _, name := range KeyEnvs() {
			if seen[name] {
				t.Fatal("duplicate key env", name)
			}
			seen[name] = true
		}
		if !seen["GEMINI_API_KEY"] || seen["ROGUE_API_KEY"] {
			t.Fatal("key env table wrong; ROGUE_API_KEY belongs to the HTTP server")
		}
	}
}

func TestProviderAliasesAndCustomRules(t *testing.T) {
	load := func(env map[string]string) (Config, error) {
		return LoadConfig(func(k string) string { return env[k] })
	}
	if c, err := load(map[string]string{"ROGUE_PROVIDER": "google", "ROGUE_MODEL": "m", "GEMINI_API_KEY": "k"}); err != nil || c.Provider != "gemini" || !strings.Contains(c.BaseURL, "generativelanguage.googleapis.com") {
		t.Fatal(c, err)
	}
	ok := []map[string]string{
		{"ROGUE_PROVIDER": "custom", "ROGUE_MODEL": "m", "ROGUE_BASE_URL": "http://10.0.0.5:8000/v1"},                                       // no key: plain HTTP is fine
		{"ROGUE_PROVIDER": "custom", "ROGUE_MODEL": "m", "ROGUE_BASE_URL": "http://127.0.0.1:8000/v1", "ROGUE_CUSTOM_API_KEY": "k"},         // key over loopback
		{"ROGUE_PROVIDER": "openai-compatible", "ROGUE_MODEL": "m", "ROGUE_BASE_URL": "https://gw.example/v1", "ROGUE_CUSTOM_API_KEY": "k"}, // alias
	}
	for _, env := range ok {
		if _, err := load(env); err != nil {
			t.Fatal(env, err)
		}
	}
	bad := map[string]map[string]string{
		"custom needs a URL":         {"ROGUE_PROVIDER": "custom", "ROGUE_MODEL": "m"},
		"key over cleartext":         {"ROGUE_PROVIDER": "custom", "ROGUE_MODEL": "m", "ROGUE_BASE_URL": "http://10.0.0.5/v1", "ROGUE_CUSTOM_API_KEY": "k"},
		"hosted gemini over http":    {"ROGUE_PROVIDER": "gemini", "ROGUE_MODEL": "m", "GEMINI_API_KEY": "k", "ROGUE_BASE_URL": "http://localhost/v1"},
		"gemini without key":         {"ROGUE_PROVIDER": "gemini", "ROGUE_MODEL": "m"},
		"localhost lookalike w/ key": {"ROGUE_PROVIDER": "custom", "ROGUE_MODEL": "m", "ROGUE_BASE_URL": "http://localhost.evil.example/v1", "ROGUE_CUSTOM_API_KEY": "k"},
	}
	for name, env := range bad {
		if _, err := load(env); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}

func parseWith(c *Client, s string) []StreamDelta {
	out := make(chan StreamDelta, 64)
	c.readSSE(context.Background(), io.NopCloser(strings.NewReader(s)), out)
	var result []StreamDelta
	for d := range out {
		result = append(result, d)
	}
	return result
}

// A compatibility-layer shape: two complete calls without index or id, and
// finish_reason "stop". Lenient clients accept it; strict clients do not.
func TestLenientToolCallStream(t *testing.T) {
	s := `data: {"choices":[{"delta":{"tool_calls":[{"type":"function","function":{"name":"dns_lookup","arguments":"{\"host\":\"a\"}"}}]}}]}` + "\n\n" +
		`data: {"choices":[{"delta":{"tool_calls":[{"id":"x2","type":"function","function":{"name":"dns_lookup","arguments":"{\"host\":\"b\"}"}}]},"finish_reason":"stop"}]}` + "\n\ndata: [DONE]\n\n"
	ds := parseWith(&Client{Lenient: true}, s)
	last := ds[len(ds)-1]
	if last.Err != nil || !last.Done || len(last.ToolCalls) != 2 || last.ToolCalls[0].ID != "call_0" || last.ToolCalls[1].ID != "x2" || last.ToolCalls[1].Function.Arguments != `{"host":"b"}` {
		t.Fatalf("%#v", ds)
	}
	for _, d := range parseWith(&Client{}, s) {
		if d.Done {
			t.Fatal("strict client accepted a mismatched finish reason")
		}
	}
	// Lenience never makes a broken call executable.
	broken := `data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"dns_lookup","arguments":"{"}}]},"finish_reason":"stop"}]}` + "\n"
	for _, d := range parseWith(&Client{Lenient: true}, broken) {
		if d.Done || len(d.ToolCalls) > 0 {
			t.Fatal("invalid arguments became executable")
		}
	}
}
