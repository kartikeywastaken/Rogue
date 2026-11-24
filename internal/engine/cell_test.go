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
	"rogue/internal/domain"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/storage"
)

func TestCellHandoffsAndBlockedFailure(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "handoff", true: "blocked"}[broken], func(t *testing.T) {
			store, err := storage.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var seen atomic.Int32
			provider := modelFunc(func(_ context.Context, messages []llm.Message) (<-chan llm.StreamDelta, error) {
				system, prompt := messages[0].Content, messages[1].Content
				if strings.Contains(system, "SIGINT") {
					if broken {
						return nil, errors.New("fixture provider failed")
					}
					if len(messages) == 2 {
						return modelReply(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{discoveryCall()}}), nil
					}
				}
				if strings.Contains(system, "ARGUS") || strings.Contains(system, "ORACLE") {
					if !strings.Contains(prompt, "fixture_discovery") || !strings.Contains(prompt, "observed service") {
						t.Error("handoff lost real tool evidence")
					}
					if len(messages) == 2 {
						seen.Add(1)
					}
					if strings.Contains(system, "ARGUS") && len(messages) == 2 {
						call := discoveryCall()
						call.ID = "scanner-1"
						return modelReply(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{call}}), nil
					}
				}
				return modelReply(llm.StreamDelta{Done: true, Content: "Evidence reviewed; no executed exploitation claimed."}), nil
			})
			harness := NewHarnessWithOptions(provider, discoveryRegistry(func(context.Context, json.RawMessage) (*arsenal.Result, error) {
				return &arsenal.Result{Success: true, Summary: "observed service"}, nil
			}), []string{"fixture"}, "fixture", Options{Store: store, Rules: mission.Rules{Scope: []string{"127.0.0.1"}}, Timeout: time.Second})
			var terminal Kind
			for event := range harness.Run(context.Background(), Request{Prompt: "inspect fixture", Mode: ModeAuto}) {
				terminal = event.Kind
			}
			state := harness.LastRun()
			snapshot := state.Control.Snapshot()
			if len(snapshot.Tasks) != len(AssessmentPlan()) {
				t.Fatal("missing roles", snapshot)
			}
			if broken {
				if terminal != KindError || snapshot.Status != mission.Failed || snapshot.BlockedTasks != 7 {
					t.Fatal("failed dependency was dispatched or hidden", snapshot)
				}
			} else {
				if terminal != KindDone || snapshot.CompletedTasks != len(AssessmentPlan()) || seen.Load() != 2 {
					t.Fatal("handoff did not complete", snapshot)
				}
				observations := state.Evidence.Observations()
				if len(observations) != 2 || observations[0].OperatorID == observations[1].OperatorID {
					t.Fatal("specialists did not produce distinct observations", observations)
				}
				for _, worker := range state.Cell.Snapshot() {
					expected := 1
					if worker.Profile.Archetype == domain.ArchCoordinator {
						expected = 2
					}
					if worker.Completed != expected || worker.State != domain.StateIdle {
						t.Fatal(worker)
					}
				}
			}
			if _, err := store.Load(snapshot.ID); err != nil {
				t.Fatal("coordinated checkpoint invalid", err)
			}
		})
	}
}

func TestExactApprovalCannotBeReplayedOrRetargeted(t *testing.T) {
	harness := NewHarnessWithOptions(nil, nil, nil, "", Options{})
	// Prepare requires real dependencies, but no provider call is needed to test
	// the gate that runs immediately before the tool dispatcher.
	harness.provider = modelFunc(func(context.Context, []llm.Message) (<-chan llm.StreamDelta, error) { return nil, nil })
	harness.reg = discoveryRegistry(nil)
	state, cleanup, err := harness.prepare(Request{Prompt: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	id := state.Control.Snapshot().ID
	args := json.RawMessage(`{"host":"127.0.0.1"}`)
	if err = harness.ApproveTool(id, "fixture_discovery", args, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = state.consumeApproval("fixture_discovery", json.RawMessage(`{"host":"127.0.0.2"}`)); err == nil {
		t.Fatal("retargeted approval accepted")
	}
	if err = state.consumeApproval("fixture_discovery", args); err != nil {
		t.Fatal(err)
	}
	if err = state.consumeApproval("fixture_discovery", args); err == nil {
		t.Fatal("replayed approval accepted")
	}
}
