package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"rogue/internal/testutil"
)

func TestRetryFallbackAndBudgetShareOneAllowance(t *testing.T) {
	var attempts atomic.Int32
	transport := testutil.RoundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body chatRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		number := attempts.Add(1)
		status := 200
		payload := "data: {\"choices\":[{\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n"
		if body.Model == "unavailable" {
			status = 404
			payload = "missing model"
		} else if number == 2 {
			status = 429
			payload = "slow down"
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"0"}}, Body: io.NopCloser(strings.NewReader(payload))}, nil
	})
	client := &Client{Name: "fixture", Endpoint: "https://fixture.invalid/chat", Client: &http.Client{Transport: transport}, Retries: 1, MaxOutputTokens: 64}
	provider := &Fallback{Provider: client, Models: []string{"available"}}
	budget, err := NewBudget(BudgetLimits{Tokens: 20000, Dollars: 1, InputPerMillion: 1, OutputPerMillion: 2})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := provider.ChatStream(WithBudget(context.Background(), budget), "unavailable", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	complete := false
	for delta := range stream {
		if delta.Err != nil {
			t.Fatal(delta.Err)
		}
		complete = complete || delta.Done
	}
	spent := budget.Snapshot()
	if !complete || attempts.Load() != 3 || spent.UncertainRequests != 2 || spent.ReservedTokens != 0 {
		t.Fatal("retry/fallback accounting mismatch", spent, attempts.Load())
	}
	small, _ := NewBudget(BudgetLimits{Tokens: 1})
	if _, err := client.ChatStream(WithBudget(context.Background(), small), "available", nil, nil); !errors.Is(err, ErrBudget) {
		t.Fatal("request exceeded preflight budget", err)
	}
	if attempts.Load() != 3 {
		t.Fatal("over-budget request reached transport")
	}
}

func TestNativeAnthropicToolStreamAndResultMapping(t *testing.T) {
	transport := testutil.RoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("anthropic-version") == "" || request.Header.Get("x-api-key") != "fixture-key" {
			t.Error("native authentication/version missing")
		}
		var body anthropicRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Messages[0].Content[0]["type"] != "tool_result" {
			t.Error("tool result was not translated")
		}
		stream := `data: {"type":"message_start","message":{"usage":{"input_tokens":3,"output_tokens":0}}}

data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"next","name":"lookup","input":{}}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"host\":\"localhost\"}"}}

data: {"type":"content_block_stop","index":0}

data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":2}}

data: {"type":"message_stop"}

`
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(stream))}, nil
	})
	provider := &Anthropic{APIKey: "fixture-key", Endpoint: "https://fixture.invalid/messages", Client: &http.Client{Transport: transport}}
	stream, err := provider.ChatStream(context.Background(), "fixture", []Message{{Role: RoleTool, ToolCallID: "previous", Content: `{"success":true}`}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	complete := false
	for delta := range stream {
		if delta.Err != nil {
			t.Fatal(delta.Err)
		}
		if delta.Done {
			complete = true
			if len(delta.ToolCalls) != 1 || delta.ToolCalls[0].Function.Arguments != `{"host":"localhost"}` {
				t.Fatal(delta)
			}
		}
	}
	if !complete {
		t.Fatal("native stream did not finish")
	}
}
