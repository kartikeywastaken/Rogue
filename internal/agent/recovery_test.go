package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
	"rogue/internal/testutil"
)

func TestOutputRecoveryDiscardsPartialCallsAndAccountsAllAttempts(t *testing.T) {
	var limits []int
	transport := testutil.RoundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			MaxTokens int           `json:"max_tokens"`
			Messages  []llm.Message `json:"messages"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		limits = append(limits, body.MaxTokens)
		reason, content, completion := "length", "discarded partial handoff", body.MaxTokens
		var calls []map[string]any
		if len(limits) <= 3 {
			calls = []map[string]any{{"index": 0, "id": "only-call", "type": "function", "function": map[string]string{"name": "failure", "arguments": "{}"}}}
		}
		if len(limits) == 3 {
			reason, content, completion = "tool_calls", "", 5
		}
		if len(limits) == 4 {
			reason, content, completion = "stop", "complete handoff", 3
			last := body.Messages[len(body.Messages)-1]
			if last.Role != llm.RoleTool || last.ToolCallID != "only-call" {
				t.Error("missing completed tool result")
			}
		}
		for _, message := range body.Messages {
			if strings.Contains(message.Content, "discarded partial handoff") {
				t.Error("truncated prose entered model history")
			}
		}
		chunk := map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": content, "tool_calls": calls}, "finish_reason": reason}}, "usage": llm.Usage{PromptTokens: 100, CompletionTokens: completion}}
		data, _ := json.Marshal(chunk)
		payload := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", data)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
	})
	registry := arsenal.New()
	executed := 0
	registry.Register(&arsenal.Tool{Name: "failure", Parameters: map[string]any{"type": "object"}, Execute: func(context.Context, json.RawMessage) (*arsenal.Result, error) {
		executed++
		return &arsenal.Result{Success: true, Summary: "observed once"}, nil
	}})
	provider := &llm.Client{Endpoint: "https://fixture.invalid/chat", Client: &http.Client{Transport: transport}}
	budget, err := llm.NewBudget(llm.BudgetLimits{Tokens: 50000})
	if err != nil {
		t.Fatal(err)
	}
	ctx := llm.WithBudget(arsenal.WithPolicy(context.Background(), arsenal.Policy{Mode: "auto"}), budget)
	var final Event
	var text string
	var usage TokenUsage
	for event := range NewLoop(provider, registry).Run(ctx, Config{BufferOutput: true}, "inspect fixture") {
		final = event
		if event.Kind == KindText {
			text += event.Text
		}
		if event.Kind == KindUsage {
			usage = event.Usage
		}
	}
	if final.Kind != KindDone || text != "complete handoff" || executed != 1 || !slices.Equal(limits, []int{2048, 4096, 8192, 8192}) {
		t.Fatalf("unexpected recovery: final=%v text=%q executions=%d limits=%v", final, text, executed, limits)
	}
	spent := budget.Snapshot()
	if spent.InputTokens != 400 || spent.OutputTokens != 6152 || spent.ReservedTokens != 0 || spent.UncertainRequests != 0 || usage.Input != 400 || usage.Output != 6152 {
		t.Fatalf("lost usage from truncated attempts: %+v, events %+v", spent, usage)
	}
}

func TestOutputRecoveryStopsAtPolicyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name         string
		config       Config
		content      string
		failure      error
		wantAttempts int
	}{
		{"ceiling", Config{BufferOutput: true}, "", &llm.OutputLimitError{Limit: 2048, Ceiling: 2048}, 1},
		{"bounded regenerations", Config{BufferOutput: true}, "", &llm.OutputLimitError{Limit: 2048, Ceiling: 8192}, 3},
		{"iteration limit", Config{BufferOutput: true, MaxIterations: 1}, "", &llm.OutputLimitError{Limit: 2048, Ceiling: 8192}, 1},
		{"already streamed prose", Config{}, "visible partial", &llm.OutputLimitError{Limit: 2048, Ceiling: 8192}, 1},
		{"transport failure", Config{BufferOutput: true}, "", errors.New("read stream: broken pipe"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			provider := providerFunc(func(context.Context, string, []llm.Message, []llm.ToolDef) (<-chan llm.StreamDelta, error) {
				attempts++
				return stream(llm.StreamDelta{Content: tc.content}, llm.StreamDelta{Err: tc.failure}), nil
			})
			events := collect(NewLoop(provider, arsenal.New()), tc.config)
			last := events[len(events)-1]
			if attempts != tc.wantAttempts || last.Kind != KindError || !errors.Is(last.Err, tc.failure) {
				t.Fatal(attempts, last)
			}
		})
	}
}

func TestOutputRecoveryPreservesExecutedToolHistory(t *testing.T) {
	registry := arsenal.New()
	executed, attempts := 0, 0
	registry.Register(&arsenal.Tool{Name: "failure", Parameters: map[string]any{"type": "object"}, Execute: func(context.Context, json.RawMessage) (*arsenal.Result, error) {
		executed++
		return &arsenal.Result{Success: true}, nil
	}})
	provider := providerFunc(func(_ context.Context, _ string, messages []llm.Message, _ []llm.ToolDef) (<-chan llm.StreamDelta, error) {
		attempts++
		if attempts == 1 {
			return stream(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{toolCall("once")}}), nil
		}
		if last := messages[len(messages)-1]; last.Role != llm.RoleTool || last.ToolCallID != "once" {
			t.Error("regeneration lost executed tool history")
		}
		if attempts == 2 {
			return stream(llm.StreamDelta{Content: "discard"}, llm.StreamDelta{Err: &llm.OutputLimitError{Limit: 2048, Ceiling: 4096}}), nil
		}
		return stream(llm.StreamDelta{Content: "final", Done: true}), nil
	})
	events := collect(NewLoop(provider, registry), Config{BufferOutput: true})
	if executed != 1 || attempts != 3 || events[len(events)-1].Kind != KindDone {
		t.Fatal(executed, attempts, events)
	}
}

func TestTruncationCannotBypassTokenBudget(t *testing.T) {
	attempts := 0
	provider := providerFunc(func(context.Context, string, []llm.Message, []llm.ToolDef) (<-chan llm.StreamDelta, error) {
		attempts++
		return stream(llm.StreamDelta{Usage: llm.Usage{PromptTokens: 3, CompletionTokens: 7}, Err: &llm.OutputLimitError{Limit: 64, Ceiling: 128}}), nil
	})
	events := collect(NewLoop(provider, arsenal.New()), Config{BufferOutput: true, MaxTokens: 10})
	if attempts != 1 || !errors.Is(events[len(events)-1].Err, ErrTokenLimit) {
		t.Fatal(attempts, events)
	}
}

func TestRecoveryAdmissionDeniesOverBudgetRequestBeforeTransport(t *testing.T) {
	attempts := 0
	transport := testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		payload := "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2048}}\n\ndata: [DONE]\n\n"
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
	})
	provider := &llm.Client{Endpoint: "https://fixture.invalid/chat", Client: &http.Client{Transport: transport}}
	budget, _ := llm.NewBudget(llm.BudgetLimits{Tokens: 5000})
	ctx := llm.WithBudget(context.Background(), budget)
	var last Event
	for event := range NewLoop(provider, arsenal.New()).Run(ctx, Config{BufferOutput: true}, "fixture") {
		last = event
	}
	if attempts != 1 || !errors.Is(last.Err, llm.ErrBudget) {
		t.Fatal("over-budget recovery reached provider", attempts, last)
	}
	spent := budget.Snapshot()
	if spent.InputTokens != 10 || spent.OutputTokens != 2048 || spent.ReservedTokens != 0 {
		t.Fatal(spent)
	}
}
