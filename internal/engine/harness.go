package engine

import (
	"context"

	"rogue/internal/agent"
	"rogue/internal/arsenal"
	"rogue/internal/llm"
	"rogue/internal/domain"
	"rogue/internal/operator"
)

// Harness is the real Engine that connects the LLM backbone, Arsenal, and
// AgentLoop into a working agent that the TUI can drive.
type Harness struct {
	provider llm.Provider
	reg      *arsenal.Registry
	models   []string
	defModel string
}

// NewHarness creates a harness with the given LLM provider and tool registry.
func NewHarness(p llm.Provider, reg *arsenal.Registry, models []string, defModel string) *Harness {
	return &Harness{provider: p, reg: reg, models: models, defModel: defModel}
}

func (h *Harness) Name() string     { return "rogue" }
func (h *Harness) Models() []string { return h.models }

// Run starts a ReAct agent loop using the recon operator profile by default.
// It maps agent.Event to engine.Event and streams them to the caller.
func (h *Harness) Run(ctx context.Context, req Request) <-chan Event {
	out := make(chan Event)
	go h.run(ctx, req, out)
	return out
}

func (h *Harness) run(ctx context.Context, req Request, out chan<- Event) {
	defer close(out)

	send := func(e Event) bool {
		select {
		case out <- e:
			return true
		case <-ctx.Done():
			return false
		}
	}

	model := req.Model
	if model == "" {
		model = h.defModel
	}

	// For P0 we always use the recon profile. P1 adds multi-operator routing.
	prof := operator.Profiles()[domain.ArchRecon]

	loop := agent.NewLoop(h.provider, h.reg)
	events := loop.Run(ctx, agent.Config{
		Model:        model,
		SystemPrompt: prof.SystemPrompt,
	}, req.Prompt)

	for ev := range events {
		switch ev.Kind {
		case agent.KindText:
			if !send(Event{Kind: KindText, Text: ev.Text}) {
				return
			}
		case agent.KindToolStart:
			if !send(Event{Kind: KindToolStart, Tool: mapTool(ev.Tool)}) {
				return
			}
		case agent.KindToolEnd:
			if !send(Event{Kind: KindToolEnd, Tool: mapTool(ev.Tool)}) {
				return
			}
		case agent.KindUsage:
			send(Event{Kind: KindUsage, Usage: Usage{Input: ev.Usage.Input, Output: ev.Usage.Output}})
		case agent.KindNotice:
			send(Event{Kind: KindNotice, Text: ev.Text})
		case agent.KindError:
			send(Event{Kind: KindError, Err: ev.Err})
			return
		case agent.KindDone:
			send(Event{Kind: KindDone})
			return
		}
	}
}

func mapTool(t agent.ToolInfo) ToolCall {
	return ToolCall{
		ID:     t.ID,
		Name:   t.Name,
		Input:  t.Input,
		Output: t.Output,
		OK:     t.OK,
	}
}
