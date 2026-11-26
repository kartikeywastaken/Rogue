package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"rogue/internal/testutil"
)

func TestOutputLimitsAndRequestTimeoutConfiguration(t *testing.T) {
	for _, tc := range []struct {
		timeout string
		want    time.Duration
		valid   bool
	}{
		{"", 0, true}, {"0s", 0, true}, {"5m", 5 * time.Minute, true}, {"-1s", 0, false}, {"bad", 0, false},
	} {
		t.Run(tc.timeout, func(t *testing.T) {
			env := map[string]string{"ROGUE_PROVIDER": "ollama", "ROGUE_MODEL": "fixture", "ROGUE_REQUEST_TIMEOUT": tc.timeout}
			config, err := LoadConfig(func(key string) string { return env[key] })
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid timeout accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if config.OutputLimit != 8192 || config.RequestTimeout != tc.want || config.RawClient().(*Client).Client.Timeout != tc.want {
				t.Fatal(config)
			}
			config.Provider = "anthropic"
			if config.RawClient().(*Anthropic).Client.Timeout != tc.want {
				t.Fatal("native provider ignored timeout")
			}
		})
	}
}

func TestRequestOutputAllowanceCannotExceedConfiguredCeiling(t *testing.T) {
	for _, tc := range []struct{ ceiling, requested, want int }{{0, 0, 2048}, {8192, 4096, 4096}, {3000, 8192, 3000}, {64, 4096, 64}} {
		ctx := WithOutputLimit(context.Background(), tc.requested)
		transport := testutil.RoundTripFunc(func(request *http.Request) (*http.Response, error) {
			var body chatRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.MaxTokens != tc.want {
				t.Errorf("requested %d with ceiling %d: got %d", tc.requested, tc.ceiling, body.MaxTokens)
			}
			payload := "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":64}}\n\ndata: [DONE]\n\n"
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
		})
		client := &Client{Endpoint: "https://fixture.invalid", MaxOutputTokens: tc.ceiling, Client: &http.Client{Transport: transport}}
		stream, err := client.ChatStream(ctx, "fixture", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var limited *OutputLimitError
		for delta := range stream {
			if delta.Done || len(delta.ToolCalls) > 0 {
				t.Fatal("truncated response became executable")
			}
			if errors.As(delta.Err, &limited) && limited.Limit != tc.want {
				t.Fatal(limited)
			}
		}
		if limited == nil {
			t.Fatal("no typed output-limit error")
		}
	}
}

func TestNativeTruncationKeepsUsageWithoutExecutingPartialCalls(t *testing.T) {
	payload := `data: {"type":"message_start","message":{"usage":{"input_tokens":10}}}

data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"partial","name":"lookup","input":{}}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{"}}

data: {"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":64}}

data: {"type":"message_stop"}

`
	transport := testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
	})
	provider := &Anthropic{Endpoint: "https://fixture.invalid", MaxOutputTokens: 64, Client: &http.Client{Transport: transport}}
	budget, _ := NewBudget(BudgetLimits{Tokens: 5000})
	stream, err := provider.ChatStream(WithBudget(context.Background(), budget), "fixture", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	limited := false
	for delta := range stream {
		if delta.Done || len(delta.ToolCalls) > 0 {
			t.Fatal("partial native tool call escaped")
		}
		limited = limited || errors.Is(delta.Err, ErrOutputLimit)
	}
	spent := budget.Snapshot()
	if !limited || spent.InputTokens != 10 || spent.OutputTokens != 64 || spent.UncertainRequests != 0 || spent.ReservedTokens != 0 {
		t.Fatal(limited, spent)
	}
}

func TestTruncationWithoutUsageStillConsumesReservation(t *testing.T) {
	budget, _ := NewBudget(BudgetLimits{Tokens: 5000})
	ctx := WithBudget(context.Background(), budget)
	allowance, err := reserve(ctx, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	input := make(chan StreamDelta, 1)
	input <- StreamDelta{Err: &OutputLimitError{Limit: 64, Ceiling: 128}}
	close(input)
	for range account(ctx, input, allowance) {
	}
	spent := budget.Snapshot()
	if spent.InputTokens != 1034 || spent.OutputTokens != 64 || spent.UncertainRequests != 1 || spent.ReservedTokens != 0 {
		t.Fatal(spent)
	}
}

func TestLearnedAllowanceIsPerModelAndRespectsCeiling(t *testing.T) {
	var hints sync.Map
	ctx, _ := generationContext(WithOutputLimit(context.Background(), 4096), 8192, "slow-model", &hints)
	rememberGeneration(ctx)
	for _, tc := range []struct {
		model         string
		ceiling, want int
	}{{"slow-model", 8192, 4096}, {"other-model", 8192, 2048}, {"slow-model", 3000, 3000}} {
		_, got := generationContext(context.Background(), tc.ceiling, tc.model, &hints)
		if got != tc.want {
			t.Fatal(tc, got)
		}
	}
	// An incomplete attempt must not teach the rest of the cell to reserve a
	// larger output allowance. Only validated termination remembers it.
	_, _ = generationContext(WithOutputLimit(context.Background(), 8192), 8192, "slow-model", &hints)
	_, got := generationContext(context.Background(), 8192, "slow-model", &hints)
	if got != 4096 {
		t.Fatal("unsuccessful generation changed learned allowance", got)
	}
}
