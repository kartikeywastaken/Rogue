package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"rogue/internal/testutil"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
	"rogue/internal/mission"
)

// A local SSE fixture exercises the real HTTP adapter, agent, tool dispatcher,
// evidence store, mission lifecycle, comms, and UI-facing event contract together.
func TestRealHarnessWorkflow(t *testing.T) {
	target := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
	}))
	defer target.Close()
	var rounds atomic.Int32
	model := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []llm.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		round := rounds.Add(1)
		if round == 1 {
			arguments, _ := json.Marshal(map[string]string{"url": target.URL})
			chunk := map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"tool_calls": []any{map[string]any{"index": 0, "id": "headers-1", "type": "function", "function": map[string]any{"name": "header_analysis", "arguments": string(arguments)}}}}, "finish_reason": "tool_calls"}}}
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", data)
			return
		}
		last := req.Messages[len(req.Messages)-1]
		var result arsenal.Result
		if round == 2 && (last.Role != llm.RoleTool || json.Unmarshal([]byte(last.Content), &result) != nil || !result.Success) {
			t.Error("missing real tool observation", last)
		}
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Header observations recorded.\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer model.Close()
	reg := arsenal.New()
	arsenal.RegisterReconTools(reg)
	h := NewHarnessWithOptions(&llm.Client{Name: "fixture", Endpoint: model.URL, Client: model.Client()}, reg, []string{"fixture"}, "fixture", Options{Rules: mission.Rules{Scope: []string{"127.0.0.1"}, PreapprovedTools: []string{"header_analysis"}}})
	var events []Event
	for e := range h.Run(context.Background(), Request{Prompt: "Review headers on the local fixture", Mode: ModeDefault}) {
		events = append(events, e)
	}
	if events[len(events)-1].Kind != KindDone {
		t.Fatal(events[len(events)-1])
	}
	state := h.LastRun()
	m := state.Control.Snapshot()
	if m.Status != mission.Completed || len(m.Tasks) != 1 || m.Tasks[0].Status != mission.TaskCompleted {
		t.Fatal(m)
	}
	obs := state.Evidence.Observations()
	if len(obs) != 1 || !obs[0].Success || obs[0].TaskID != m.Tasks[0].ID {
		t.Fatal(obs)
	}
	findings := state.Evidence.Findings()
	if len(findings) == 0 {
		t.Fatal("no evidence-backed findings")
	}
	for _, f := range findings {
		if len(f.Evidence) != 1 || f.Evidence[0] != obs[0].ID {
			t.Fatal(f)
		}
	}
	history := state.Comms.History("")
	found := false
	for _, msg := range history {
		if msg.Topic == "tool.observed" {
			found = true
			if msg.EvidenceIDs[0] != obs[0].ID {
				t.Fatal(msg)
			}
		}
	}
	if !found {
		t.Fatal("no shared observation")
	}
	// A later turn must not reuse the earlier mission, even though UI transcript remains.
	for range h.Run(context.Background(), Request{Prompt: "Explain the observation", Mode: ModePlan}) {
	}
	if h.LastRun() == state || h.LastRun().Control.Snapshot().ID == m.ID {
		t.Fatal("mission state leaked across turns")
	}
}

type waitingProvider struct{ started chan struct{} }

func (p waitingProvider) ChatStream(ctx context.Context, _ string, _ []llm.Message, _ []llm.ToolDef) (<-chan llm.StreamDelta, error) {
	out := make(chan llm.StreamDelta)
	close(p.started)
	go func() { <-ctx.Done(); close(out) }()
	return out, nil
}
func TestCancellationAndDeadlineTerminateMission(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			started := make(chan struct{})
			opts := Options{Timeout: time.Second}
			if deadline {
				opts.Timeout = 20 * time.Millisecond
			}
			h := NewHarnessWithOptions(waitingProvider{started}, arsenal.New(), []string{"fixture"}, "fixture", opts)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch := h.Run(ctx, Request{Prompt: "explain", Mode: ModePlan})
			<-started
			if !deadline {
				cancel()
			}
			terminalError := false
			for e := range ch {
				if e.Kind == KindDone {
					t.Fatal("cancelled mission marked successful")
				}
				terminalError = terminalError || e.Kind == KindError
			}
			want := mission.Aborted
			if deadline {
				want = mission.Failed
				if !terminalError {
					t.Fatal("deadline error missing")
				}
			}
			if got := h.LastRun().Control.Snapshot().Status; got != want {
				t.Fatal(got, want)
			}
		})
	}
}

func TestPlanDoesNotAdvertiseTools(t *testing.T) {
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"tools"`) {
			t.Error("plan advertised executable tools")
		}
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Plan only.\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	r := arsenal.New()
	arsenal.RegisterReconTools(r)
	h := NewHarness(&llm.Client{Name: "fixture", Endpoint: srv.URL, Client: srv.Client()}, r, []string{"fixture"}, "fixture")
	for e := range h.Run(context.Background(), Request{Prompt: "plan", Mode: ModePlan}) {
		if e.Kind == KindError {
			t.Fatal(e.Err)
		}
	}
	if len(h.LastRun().Evidence.Observations()) != 0 {
		t.Fatal("plan ran tools")
	}
}

type floodingProvider struct{ stopped chan struct{} }

func (p floodingProvider) ChatStream(ctx context.Context, _ string, _ []llm.Message, _ []llm.ToolDef) (<-chan llm.StreamDelta, error) {
	ch := make(chan llm.StreamDelta)
	go func() {
		defer close(ch)
		defer close(p.stopped)
		for {
			select {
			case ch <- llm.StreamDelta{Content: "x"}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}
func TestAbandonedConsumerDoesNotStrandMission(t *testing.T) {
	stopped := make(chan struct{})
	h := NewHarnessWithOptions(floodingProvider{stopped}, arsenal.New(), []string{"fixture"}, "fixture", Options{Timeout: 30 * time.Millisecond})
	ch := h.Run(context.Background(), Request{Prompt: "explain", Mode: ModePlan})
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked producer outlived deadline")
	}
	for e := range ch {
		if e.Kind == KindDone {
			t.Fatal("abandoned mission completed")
		}
	}
	if h.LastRun().Control.Snapshot().Status != mission.Failed {
		t.Fatal("deadline not recorded")
	}
}
