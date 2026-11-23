package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
)

type providerFunc func(context.Context, string, []llm.Message, []llm.ToolDef) (<-chan llm.StreamDelta, error)

func (f providerFunc) ChatStream(c context.Context, m string, ms []llm.Message, t []llm.ToolDef) (<-chan llm.StreamDelta, error) {
	return f(c, m, ms, t)
}
func stream(ds ...llm.StreamDelta) <-chan llm.StreamDelta {
	ch := make(chan llm.StreamDelta, len(ds))
	for _, d := range ds {
		ch <- d
	}
	close(ch)
	return ch
}
func toolCall(id string) llm.ToolCall {
	return llm.ToolCall{ID: id, Type: "function", Function: llm.FuncCall{Name: "failure", Arguments: `{}`}}
}
func collect(l *Loop, cfg Config) []Event {
	var out []Event
	for e := range l.Run(arsenal.WithPolicy(context.Background(), arsenal.Policy{Mode: "auto"}), cfg, "task") {
		out = append(out, e)
	}
	return out
}
func TestFailureEnvelopeReachesModel(t *testing.T) {
	r := arsenal.New()
	r.Register(&arsenal.Tool{Name: "failure", Parameters: map[string]any{"type": "object"}, Execute: func(context.Context, json.RawMessage) (*arsenal.Result, error) {
		return &arsenal.Result{Success: false, Summary: "DNS resolution failed"}, nil
	}})
	iteration := 0
	p := providerFunc(func(_ context.Context, _ string, msgs []llm.Message, _ []llm.ToolDef) (<-chan llm.StreamDelta, error) {
		iteration++
		if iteration == 1 {
			return stream(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{toolCall("c1")}}), nil
		}
		last := msgs[len(msgs)-1]
		var env arsenal.Result
		if err := json.Unmarshal([]byte(last.Content), &env); err != nil {
			t.Fatal(err)
		}
		if last.Role != llm.RoleTool || last.ToolCallID != "c1" || env.Success || env.Error != "DNS resolution failed" {
			t.Error("lost tool failure", last)
		}
		return stream(llm.StreamDelta{Content: "The lookup failed.", Done: true}), nil
	})
	events := collect(NewLoop(p, r), Config{})
	if events[len(events)-1].Kind != KindDone {
		t.Fatal(events)
	}
}
func TestBrokenStreamsAndBudgets(t *testing.T) {
	for _, tc := range []struct {
		name string
		ds   []llm.StreamDelta
		cfg  Config
		want error
	}{
		{"EOF", []llm.StreamDelta{{Content: "partial"}}, Config{}, nil},
		{"stream error", []llm.StreamDelta{{Err: errors.New("broken")}}, Config{}, nil},
		{"token cap", []llm.StreamDelta{{Done: true, Usage: llm.Usage{PromptTokens: 10}}}, Config{MaxTokens: 10}, ErrTokenLimit},
		{"tool cap", []llm.StreamDelta{{Done: true, ToolCalls: []llm.ToolCall{toolCall("a"), toolCall("b")}}}, Config{MaxToolCalls: 1}, ErrToolLimit},
		{"iteration cap", []llm.StreamDelta{{Done: true, ToolCalls: []llm.ToolCall{toolCall("a")}}}, Config{MaxIterations: 1}, ErrIterationLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := providerFunc(func(context.Context, string, []llm.Message, []llm.ToolDef) (<-chan llm.StreamDelta, error) {
				return stream(tc.ds...), nil
			})
			es := collect(NewLoop(p, arsenal.New()), tc.cfg)
			last := es[len(es)-1]
			if last.Kind != KindError || last.Err == nil || (tc.want != nil && !errors.Is(last.Err, tc.want)) {
				t.Fatal(last)
			}
		})
	}
}
func TestCancelledLoopStopsProvider(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	p := providerFunc(func(ctx context.Context, _ string, _ []llm.Message, _ []llm.ToolDef) (<-chan llm.StreamDelta, error) {
		ch := make(chan llm.StreamDelta)
		close(started)
		go func() { <-ctx.Done(); close(ch); close(stopped) }()
		return ch, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	ch := NewLoop(p, arsenal.New()).Run(ctx, Config{}, "task")
	<-started
	cancel()
	for range ch {
	}
	<-stopped
}
