package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/storage"
	"rogue/internal/target"
)

type modelFunc func(context.Context, []llm.Message) (<-chan llm.StreamDelta, error)

func (model modelFunc) ChatStream(ctx context.Context, _ string, messages []llm.Message, _ []llm.ToolDef) (<-chan llm.StreamDelta, error) {
	return model(ctx, messages)
}
func modelReply(reply llm.StreamDelta) <-chan llm.StreamDelta {
	stream := make(chan llm.StreamDelta, 1)
	stream <- reply
	close(stream)
	return stream
}
func discoveryCall() llm.ToolCall {
	return llm.ToolCall{ID: "discovery-1", Type: "function", Function: llm.FuncCall{Name: "fixture_discovery", Arguments: `{"host":"127.0.0.1"}`}}
}
func discoveryRegistry(execute func(context.Context, json.RawMessage) (*arsenal.Result, error)) *arsenal.Registry {
	registry := arsenal.New()
	registry.Register(&arsenal.Tool{Name: "fixture_discovery", Category: "recon", Parameters: map[string]any{"type": "object", "properties": map[string]any{"host": map[string]any{"type": "string"}}, "required": []string{"host"}}, Execute: execute})
	return registry
}

// One test crosses the real mission, vault, inventory, comms, and encrypted file
// boundaries. The discovery fixture itself cannot contact a network target.
func TestDurableMissionAndInterruptedRecovery(t *testing.T) {
	directory := t.TempDir()
	store, err := storage.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	registry := discoveryRegistry(func(context.Context, json.RawMessage) (*arsenal.Result, error) {
		return &arsenal.Result{Success: true, Summary: "observed fixture service", Data: map[string]any{"services": []target.Service{{Port: 80, Protocol: "tcp", Name: "http", Product: "fixture"}}}}, nil
	})
	var rounds atomic.Int32
	provider := modelFunc(func(context.Context, []llm.Message) (<-chan llm.StreamDelta, error) {
		if rounds.Add(1) == 1 {
			return modelReply(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{discoveryCall()}}), nil
		}
		return modelReply(llm.StreamDelta{Content: "Fixture service observed.", Done: true}), nil
	})
	harness := NewHarnessWithOptions(provider, registry, []string{"fixture"}, "fixture", Options{SingleOperator: true, Store: store, Rules: mission.Rules{Scope: []string{"127.0.0.1"}}})
	for event := range harness.Run(context.Background(), Request{Prompt: "inspect fixture", Mode: ModeAuto}) {
		if event.Kind == KindError {
			t.Fatal(event.Err)
		}
	}
	id := harness.LastRun().Control.Snapshot().ID
	reopened, err := storage.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := reopened.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Mission.Status != mission.Completed || len(checkpoint.Targets.Hosts) != 1 || len(checkpoint.Targets.Hosts[0].Services) != 1 {
		t.Fatal("mission or target inventory was not restored")
	}
	payload, err := os.ReadFile(filepath.Join(directory, id+".state"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "Fixture service observed") {
		t.Fatal("checkpoint was saved as plaintext")
	}
	// A live process owns the lease; only an unowned interrupted mission is recovered.
	checkpoint.Mission.Status = mission.Active
	checkpoint.Mission.Tasks[0].Status = mission.Running
	checkpoint.Comms.Closed = false
	if err := reopened.Save(checkpoint); err != nil {
		t.Fatal(err)
	}
	release, err := store.Acquire(id)
	if err != nil {
		t.Fatal(err)
	}
	count, err := reopened.Recover()
	if err != nil || count != 0 {
		t.Fatal("recovered another live process", count, err)
	}
	release()
	count, err = reopened.Recover()
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
	checkpoint, err = reopened.Load(id)
	if err != nil || checkpoint.Mission.Status != mission.Aborted || checkpoint.Mission.Tasks[0].Status != mission.Cancelled {
		t.Fatal("unfinished work was not made explicit", err)
	}
	// Authentication rejects corruption instead of returning plausible partial state.
	payload[len(payload)-1] ^= 1
	if err := os.WriteFile(filepath.Join(directory, id+".state"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Load(id); err == nil {
		t.Fatal("accepted corrupted encrypted state")
	}
}

func TestPauseCancelsToolAndResumePreservesItsFailure(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	registry := discoveryRegistry(func(ctx context.Context, _ json.RawMessage) (*arsenal.Result, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	var rounds atomic.Int32
	provider := modelFunc(func(_ context.Context, messages []llm.Message) (<-chan llm.StreamDelta, error) {
		if rounds.Add(1) == 1 {
			return modelReply(llm.StreamDelta{Done: true, ToolCalls: []llm.ToolCall{discoveryCall()}}), nil
		}
		if !strings.Contains(messages[len(messages)-1].Content, "paused") {
			t.Error("interrupted tool outcome was hidden")
		}
		return modelReply(llm.StreamDelta{Done: true, Content: "The operation was interrupted."}), nil
	})
	harness := NewHarnessWithOptions(provider, registry, []string{"fixture"}, "fixture", Options{SingleOperator: true})
	stream := harness.Run(context.Background(), Request{Prompt: "inspect fixture", Mode: ModeAuto})
	<-started
	id := harness.LastRun().Control.Snapshot().ID
	if err := harness.PauseMission(id); err != nil {
		t.Fatal(err)
	}
	<-cancelled
	if rounds.Load() != 1 {
		t.Fatal("model advanced while paused")
	}
	if err := harness.ResumeMission(id); err != nil {
		t.Fatal(err)
	}
	for event := range stream {
		if event.Kind == KindError {
			t.Fatal(event.Err)
		}
	}
	observations := harness.LastRun().Evidence.Observations()
	if len(observations) != 1 || observations[0].Success {
		t.Fatal("pause did not preserve an unsuccessful observation")
	}
}
