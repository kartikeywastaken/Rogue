package engine

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/domain"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/opsec"
)

func TestInspectorSeamAndTeamFactory(t *testing.T) {
	defer opsec.SetProfile("loud")
	opsec.SetProfile("loud")

	var ran atomic.Int32
	provider := modelFunc(func(_ context.Context, messages []llm.Message) (<-chan llm.StreamDelta, error) {
		if strings.Contains(messages[0].Content, "SIGINT") && len(messages) == 2 {
			return modelReply(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{discoveryCall()}}), nil
		}
		ran.Add(1)
		return modelReply(llm.StreamDelta{Done: true, Content: "Observed."}), nil
	})
	reg := discoveryRegistry(func(context.Context, json.RawMessage) (*arsenal.Result, error) {
		return &arsenal.Result{Success: true, Summary: "ok"}, nil
	})

	h := NewHarnessWithOptions(provider, reg, []string{"fixture"}, "fixture", Options{
		Team:         "breach",
		OPSECProfile: "loud",
		Rules:        mission.Rules{Scope: []string{"127.0.0.1"}},
		Timeout:      2 * time.Second,
	})
	var _ Inspector = h

	for e := range h.Run(context.Background(), Request{Prompt: "test team and inspector", Mode: ModeAuto}) {
		if e.Kind == KindError {
			t.Fatal(e.Err)
		}
	}

	snap, ok := h.LiveSnapshot()
	if !ok || snap.MissionID == "" || snap.OPSECProfile != "loud" {
		t.Fatalf("unexpected LiveSnapshot: ok=%v snap=%+v", ok, snap)
	}
	exploiters := 0
	for _, op := range snap.Operators {
		if op.Profile.Archetype == domain.ArchExploiter {
			exploiters++
		}
	}
	if exploiters != 2 {
		t.Fatalf("expected 2 exploiters in breach team snapshot, got %d", exploiters)
	}
}
