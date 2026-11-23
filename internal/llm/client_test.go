package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"rogue/internal/testutil"
	"strings"
	"testing"
)

func parseStream(s string) []StreamDelta {
	out := make(chan StreamDelta, 64)
	(&Client{}).readSSE(context.Background(), io.NopCloser(strings.NewReader(s)), out)
	var result []StreamDelta
	for d := range out {
		result = append(result, d)
	}
	return result
}
func TestStreamAssemblesFragmentedSparseToolIndex(t *testing.T) {
	s := `data: {"choices":[{"delta":{"tool_calls":[{"index":2,"id":"call","type":"function","function":{"name":"dns_lookup","arguments":"{\"host\":"}}]}}]}` + "\n\n" +
		`data: {"choices":[{"delta":{"tool_calls":[{"index":2,"function":{"arguments":"\"localhost\"}"}}]},"finish_reason":"tool_calls"}]}` + "\n\n" +
		`data: {"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":3}}` + "\n\ndata: [DONE]\n\n"
	ds := parseStream(s)
	if len(ds) != 2 {
		t.Fatalf("deltas: %#v", ds)
	}
	last := ds[len(ds)-1]
	if !last.Done || last.Err != nil || len(last.ToolCalls) != 1 || last.ToolCalls[0].Function.Arguments != `{"host":"localhost"}` {
		t.Fatalf("bad completion: %#v", last)
	}
}
func TestBrokenStreamNeverEmitsExecutableCalls(t *testing.T) {
	for name, s := range map[string]string{
		"EOF":                 `data: {"choices":[{"delta":{"content":"partial"}}]}` + "\n",
		"done without finish": "data: [DONE]\n",
		"bad JSON":            "data: {bad}\n",
		"error":               `data: {"error":{"message":"failed"}}` + "\n",
		"length":              `data: {"choices":[{"delta":{},"finish_reason":"length"}]}` + "\n",
		"missing arguments":   `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"x","function":{"name":"dns_lookup","arguments":"{"}}]},"finish_reason":"tool_calls"}]}` + "\n",
		"scanner overflow":    "data: " + strings.Repeat("x", 1024*1024) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			ds := parseStream(s)
			failed := false
			for _, d := range ds {
				failed = failed || d.Err != nil
				if d.Done || len(d.ToolCalls) > 0 {
					t.Fatal("broken response became executable")
				}
			}
			if !failed {
				t.Fatal("no error")
			}
		})
	}
}
func TestHTTPWireContract(t *testing.T) {
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("authorization missing")
		}
		var request chatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if !request.Stream || request.Model != "fixture" || !request.StreamOptions["include_usage"] {
			t.Error("request contract")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	c := &Client{Name: "fixture", APIKey: "test-key", Endpoint: srv.URL, Client: srv.Client()}
	ch, err := c.ChatStream(context.Background(), "fixture", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := ""
	done := false
	for d := range ch {
		if d.Err != nil {
			t.Fatal(d.Err)
		}
		text += d.Content
		done = done || d.Done
	}
	if text != "hello" || !done {
		t.Fatal(text, done)
	}
}
func TestProviderConfig(t *testing.T) {
	for _, provider := range []string{"openrouter", "openai", "groq", "ollama", "local"} {
		t.Run(provider, func(t *testing.T) {
			env := map[string]string{"ROGUE_PROVIDER": provider, "ROGUE_MODEL": "fixture", "ROGUE_MODELS": "other,fixture", "OPENROUTER_API_KEY": "key", "OPENAI_API_KEY": "key", "GROQ_API_KEY": "key"}
			c, err := LoadConfig(func(k string) string { return env[k] })
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Models) != 2 || c.Models[0] != "fixture" {
				t.Fatal(c.Models)
			}
		})
	}
	for _, env := range []map[string]string{{}, {"ROGUE_PROVIDER": "mock"}, {"ROGUE_PROVIDER": "groq", "ROGUE_MODEL": "x"}, {"ROGUE_PROVIDER": "ollama"}, {"ROGUE_PROVIDER": "openai", "OPENAI_API_KEY": "key", "ROGUE_MODEL": "x", "ROGUE_BASE_URL": "http://example.com/v1"}} {
		if _, err := LoadConfig(func(k string) string { return env[k] }); err == nil {
			t.Fatal("accepted invalid config", env)
		}
	}
}
