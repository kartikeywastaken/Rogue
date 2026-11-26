package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/opsec"
)

func TestInteractiveApprovalExactScopeOnceAndMission(t *testing.T) {
	for _, decision := range []ApprovalDecision{ApprovalOnce, ApprovalMission, ApprovalDeny} {
		t.Run(map[ApprovalDecision]string{ApprovalOnce: "once", ApprovalMission: "mission", ApprovalDeny: "deny"}[decision], func(t *testing.T) {
			h := NewHarnessWithOptions(nil, discoveryRegistry(nil), []string{"fixture"}, "fixture", Options{})
			state, cleanup, err := h.prepare(Request{Prompt: "approval fixture"})
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			calls := 0
			ctx := WithApprovalHandler(context.Background(), func(_ context.Context, req ApprovalRequest) (ApprovalDecision, error) {
				calls++
				if req.Tool != "fixture_discovery" || req.Target != "127.0.0.1" || req.MissionID != state.Control.Snapshot().ID {
					t.Errorf("wrong action %+v", req)
				}
				snap, _ := h.LiveSnapshot()
				if snap.PendingApprovals != 1 {
					t.Error("pending request missing from inspector")
				}
				return decision, nil
			})
			approve := h.actionApprover(ctx, state)
			args := json.RawMessage(`{"host":"127.0.0.1"}`)
			err = approve("fixture_discovery", args)
			if decision == ApprovalDeny {
				if err == nil {
					t.Fatal("denied action granted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = state.consumeApproval("fixture_discovery", json.RawMessage(`{"host":"127.0.0.2"}`)); err == nil {
				t.Fatal("mission grant widened to another target")
			}
			err = state.consumeApproval("fixture_discovery", args)
			if decision == ApprovalOnce && err == nil {
				t.Fatal("once grant replayed")
			}
			if decision == ApprovalMission && err != nil {
				t.Fatal("exact mission grant not reusable", err)
			}
			if calls != 1 {
				t.Fatal("unexpected approval calls", calls)
			}
			snap, _ := h.LiveSnapshot()
			if snap.PendingApprovals != 0 {
				t.Fatal("answered request still pending")
			}
		})
	}
}

func TestInteractiveApprovalCancelsWithoutGrant(t *testing.T) {
	h := NewHarnessWithOptions(nil, discoveryRegistry(nil), nil, "", Options{})
	state, cleanup, err := h.prepare(Request{Prompt: "cancel fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	ctx = WithApprovalHandler(ctx, func(ctx context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		close(entered)
		<-ctx.Done()
		return ApprovalOnce, ctx.Err()
	})
	done := make(chan error, 1)
	go func() {
		done <- h.actionApprover(ctx, state)("fixture_discovery", json.RawMessage(`{"host":"127.0.0.1"}`))
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("approval ignored cancellation")
	}
	if err = state.consumeApproval("fixture_discovery", json.RawMessage(`{"host":"127.0.0.1"}`)); err == nil {
		t.Fatal("cancelled action left a grant")
	}
}

func TestInteractiveApprovalRunsThroughRealAgentAndPolicy(t *testing.T) {
	var executions atomic.Int32
	reg := discoveryRegistry(func(context.Context, json.RawMessage) (*arsenal.Result, error) {
		executions.Add(1)
		return &arsenal.Result{Success: true, Summary: "fixture observed"}, nil
	})
	provider := modelFunc(func(_ context.Context, messages []llm.Message) (<-chan llm.StreamDelta, error) {
		if len(messages) == 2 {
			return modelReply(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{discoveryCall()}}), nil
		}
		return modelReply(llm.StreamDelta{Done: true, Content: "Observation recorded"}), nil
	})
	h := NewHarnessWithOptions(provider, reg, []string{"fixture"}, "fixture", Options{SingleOperator: true, Rules: mission.Rules{Scope: []string{"127.0.0.1"}}, Timeout: time.Second})
	requests := 0
	ctx := WithApprovalHandler(context.Background(), func(context.Context, ApprovalRequest) (ApprovalDecision, error) { requests++; return ApprovalOnce, nil })
	var terminal Event
	for ev := range h.Run(ctx, Request{Prompt: "inspect local fixture", Mode: ModeDefault}) {
		terminal = ev
	}
	if terminal.Kind != KindDone || executions.Load() != 1 || requests != 1 {
		t.Fatalf("interactive flow failed: terminal=%+v executions=%d requests=%d", terminal, executions.Load(), requests)
	}
	trace, err := h.ToolTrace(h.LastRun().Control.Snapshot().ID, "discovery-1")
	if err != nil || !strings.Contains(string(trace), "fixture observed") || !strings.Contains(string(trace), "127.0.0.1") {
		t.Fatal("full tool trace unavailable", string(trace), err)
	}
}

func TestWarRoomPresetCloneRejectsActiveMission(t *testing.T) {
	oldProfile, oldRoE := opsec.ActiveProfileSnapshot().Name, opsec.ActiveRoESnapshot().Name
	defer opsec.SetProfile(oldProfile)
	defer opsec.SetRoE(oldRoE)
	h := NewHarnessWithOptions(nil, discoveryRegistry(nil), nil, "", Options{MaxTokens: 12345})
	eng, err := h.WithWarRoomPresets("loud", "strict", "stealth")
	if err != nil {
		t.Fatal(err)
	}
	next := eng.(*Harness)
	if next == h || h.opts.Team != "" || next.opts.Team != "stealth" || next.opts.MaxTokens != 12345 || next.opts.RoEPreset != "strict" {
		t.Fatal("preset rebuild mutated existing engine or dropped budgets")
	}
	_, cleanup, err := next.prepare(Request{Prompt: "active fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err = next.WithWarRoomPresets("covert", "default", "balanced"); err == nil {
		t.Fatal("reconfigured active engine")
	}
}
