package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/testutil"
)

// Exercise the real HTTP adapter and entire cell. The first coordinator reply
// truncates, its replacement completes, and later operators reuse the allowance.
func TestCellRecoversTruncatedCoordinatorWithCompactPreflight(t *testing.T) {
	var mu sync.Mutex
	attempts, preflights := 0, 0
	transport := testutil.RoundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		var body struct {
			Messages  []llm.Message `json:"messages"`
			Tools     []llm.ToolDef `json:"tools"`
			MaxTokens int           `json:"max_tokens"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			return nil, err
		}
		attempts++
		reason, content, used := "stop", "Review complete; missing evidence remains unverified.", 10
		if attempts == 1 {
			reason, content, used = "length", "discard this incomplete review", 2048
			if body.MaxTokens != 2048 {
				t.Error("initial allowance changed", body.MaxTokens)
			}
		} else if body.MaxTokens != 4096 {
			t.Error("model allowance was not reused", body.MaxTokens)
		}
		prompt := body.Messages[1].Content
		if strings.Contains(prompt, "Assigned task: Review the objective") {
			preflights++
			if len(body.Tools) != 0 || len(prompt) > 2000 {
				t.Error("preflight includes an unnecessary catalog or oversized context", len(body.Tools), len(prompt))
			}
			var shared sharedContext
			if err := json.Unmarshal([]byte(prompt[strings.LastIndex(prompt, "\n")+1:]), &shared); err != nil {
				t.Error(err)
			}
			if len(shared.Tasks) != 0 || len(shared.Rules.Scope) != 1 || shared.Rules.Scope[0] != "127.0.0.1" {
				t.Error("preflight lost scope or repeated the task graph")
			}
		}
		chunk := map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": content}, "finish_reason": reason}}, "usage": llm.Usage{PromptTokens: 40, CompletionTokens: used}}
		data, _ := json.Marshal(chunk)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", data)))}, nil
	})
	registry := arsenal.New()
	arsenal.RegisterResearchTools(registry)
	arsenal.RegisterMissionTools(registry)
	client := &llm.Client{Endpoint: "https://fixture.invalid/chat", Client: &http.Client{Transport: transport}}
	harness := NewHarnessWithOptions(client, registry, []string{"fixture"}, "fixture", Options{Rules: mission.Rules{Scope: []string{"127.0.0.1"}}, Timeout: 3 * time.Second})
	var terminal Event
	for event := range harness.Run(context.Background(), Request{Prompt: "Review the configured local target", Mode: ModeAuto}) {
		terminal = event
	}
	state := harness.LastRun()
	snapshot := state.Control.Snapshot()
	if terminal.Kind != KindDone || snapshot.CompletedTasks != 9 || attempts != 10 || preflights != 2 {
		t.Fatalf("cell did not recover: terminal=%+v tasks=%d attempts=%d preflights=%d", terminal, snapshot.CompletedTasks, attempts, preflights)
	}
	if strings.Contains(snapshot.Tasks[0].Result, "discard") {
		t.Fatal("truncated review entered the task handoff")
	}
	spent := state.Budget.Snapshot()
	if spent.InputTokens != 400 || spent.OutputTokens != 2138 || spent.UncertainRequests != 0 {
		t.Fatal("cell lost truncated usage", spent)
	}
}
