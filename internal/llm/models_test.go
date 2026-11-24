package llm

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"rogue/internal/testutil"
)

func serve(t *testing.T, check func(*http.Request), status int, body string) string {
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path %s", r.URL.Path)
		}
		if check != nil {
			check(r)
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1"
}

func TestListModelsSanitizesUntrustedCatalog(t *testing.T) {
	body := `{"data":[
		{"id":"zeta-model"},
		{"id":"alpha-model","supported_parameters":["tools","temperature"]},
		{"id":"alpha-model"},
		{"id":"no-tools","supported_parameters":["temperature"]},
		{"id":"mistral-no-fc","capabilities":{"function_calling":false}},
		{"id":"mistral-fc","capabilities":{"function_calling":true}},
		{"id":"\u001b[2J\u001b[31mpwned"},
		{"id":"has space"},
		{"id":"` + strings.Repeat("x", 300) + `"},
		{"id":""}
	]}`
	base := serve(t, func(r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k-123" {
			t.Error("missing bearer auth")
		}
	}, 200, body)
	got, err := ListModels(context.Background(), Config{Provider: "openrouter", BaseURL: base, APIKey: "k-123"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha-model", "mistral-fc", "zeta-model"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestListModelsProviderShapes(t *testing.T) {
	base := serve(t, func(r *http.Request) {
		if r.Header.Get("x-api-key") != "ak" || r.Header.Get("anthropic-version") == "" || r.Header.Get("Authorization") != "" || r.URL.Query().Get("limit") != "1000" {
			t.Error("anthropic headers wrong")
		}
	}, 200, `{"data":[{"id":"claude-b"},{"id":"claude-a"}],"has_more":false}`)
	if got, err := ListModels(context.Background(), Config{Provider: "anthropic", BaseURL: base, APIKey: "ak"}, nil); err != nil || !slices.Equal(got, []string{"claude-a", "claude-b"}) {
		t.Fatal(got, err)
	}
	base = serve(t, nil, 200, `{"object":"list","data":[{"id":"models/gemini-x"}]}`)
	if got, _ := ListModels(context.Background(), Config{Provider: "gemini", BaseURL: base, APIKey: "g"}, nil); !slices.Equal(got, []string{"gemini-x"}) {
		t.Fatal("gemini prefix not stripped", got)
	}
	base = serve(t, nil, 200, `[{"id":"together/b"},{"id":"together/a"}]`)
	if got, _ := ListModels(context.Background(), Config{Provider: "together", BaseURL: base, APIKey: "t"}, nil); !slices.Equal(got, []string{"together/a", "together/b"}) {
		t.Fatal("bare array not parsed", got)
	}
}

func TestListModelsFailuresNeverLeakKey(t *testing.T) {
	const key = "sk-super-secret-key-999"
	base := serve(t, nil, 401, `{"error":"invalid key `+key+`"}`)
	_, err := ListModels(context.Background(), Config{Provider: "openai", BaseURL: base, APIKey: key}, nil)
	if err == nil || strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "rejected this API key") {
		t.Fatal(err)
	}
	base = serve(t, nil, 500, "boom "+key+"\x1b[31m")
	_, err = ListModels(context.Background(), Config{Provider: "openai", BaseURL: base, APIKey: key}, nil)
	if err == nil || strings.Contains(err.Error(), key) || strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatal("error leaked key or escape codes:", err)
	}
	base = serve(t, nil, 200, `{"data":[`+strings.Repeat(`{"id":"m"},`, 2<<20)+`{"id":"m"}]}`)
	if _, err := ListModels(context.Background(), Config{Provider: "openai", BaseURL: base}, nil); err == nil {
		t.Fatal("oversized catalog accepted")
	}
	base = serve(t, nil, 200, `<html>not json</html>`)
	if _, err := ListModels(context.Background(), Config{Provider: "openai", BaseURL: base}, nil); err == nil {
		t.Fatal("garbage accepted")
	}
}
