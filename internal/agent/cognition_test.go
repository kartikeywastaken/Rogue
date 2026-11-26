package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
)

func TestBacktrackingAndTreeOfThoughtAndAIRedTeam(t *testing.T) {
	reg := arsenal.New()
	reg.Register(&arsenal.Tool{
		Name:       "failing_tool",
		Category:   "recon",
		Parameters: map[string]any{"type": "object"},
		Execute: func(context.Context, json.RawMessage) (*arsenal.Result, error) {
			return nil, errors.New("tool error")
		},
	})

	sawHint := false
	calls := 0
	provider := providerFunc(func(_ context.Context, _ string, messages []llm.Message, _ []llm.ToolDef) (<-chan llm.StreamDelta, error) {
		calls++
		if calls == 1 {
			return stream(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{{
				ID: "c1", Type: "function", Function: llm.FuncCall{Name: "failing_tool", Arguments: `{}`},
			}}}), nil
		}
		for _, m := range messages {
			if strings.Contains(m.Content, "Backtracking hint") {
				sawHint = true
			}
		}
		return stream(llm.StreamDelta{Done: true, Content: "pivoted"}), nil
	})

	events := collect(NewLoop(provider, reg), Config{ToolCategories: []string{"recon"}, Backtrack: true})
	if !sawHint || events[len(events)-1].Kind != KindDone {
		t.Fatalf("expected backtracking hint and completion: sawHint=%v events=%+v", sawHint, events)
	}

	tot, err := TreeOfThoughtWithProvider(context.Background(), providerFunc(func(_ context.Context, _ string, msgs []llm.Message, _ []llm.ToolDef) (<-chan llm.StreamDelta, error) {
		return stream(llm.StreamDelta{Done: true, Content: "Verify evidence and CWE risk carefully."}), nil
	}), "fixture", "analyze surface", 3, nil)
	if err != nil || len(tot.Branches) != 3 || tot.Best.Score <= 0 {
		t.Fatalf("unexpected TreeOfThought result: %+v err=%v", tot, err)
	}

	red := AIRedTeam(context.Background(), "fixture", func(_ context.Context, p string) (string, error) {
		if strings.Contains(p, "ROLE_OVERRIDE_OK") {
			return "ROLE_OVERRIDE_OK", nil
		}
		return "I Cannot comply with that request.", nil // mixed case test!
	}, nil)
	if red.Refused != 3 || red.Responded != 1 {
		t.Fatalf("expected case-insensitive 3 refused + 1 responded, got %+v", red)
	}
}
