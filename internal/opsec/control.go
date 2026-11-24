// Package opsec records observable signals without equating a failed request
// with detection. Decisions are deterministic and scoped to one mission.
package opsec

import (
	"errors"
	"sync"
	"time"
)

type Policy struct{ PauseAfter, AbortAfter int }
type Signal struct {
	Operator, Kind, Source, Indicator, ObservationID string
	At                                               time.Time
}
type Snapshot struct {
	Policy  Policy
	Signals []Signal
}
type Control struct {
	mu    sync.Mutex
	state Snapshot
}

func New(policy Policy) *Control { return &Control{state: Snapshot{Policy: policy}} }
func (control *Control) Record(signal Signal) (string, error) {
	control.mu.Lock()
	defer control.mu.Unlock()
	if signal.Source == "" || signal.Kind == "" || signal.Indicator == "" {
		return "", errors.New("OPSEC signal requires source, kind and indicator")
	}
	if len(control.state.Signals) >= 1024 {
		return "", errors.New("OPSEC signal capacity exhausted")
	}
	if signal.At.IsZero() {
		signal.At = time.Now().UTC()
	}
	control.state.Signals = append(control.state.Signals, signal)
	count := len(control.state.Signals)
	if control.state.Policy.AbortAfter > 0 && count >= control.state.Policy.AbortAfter {
		return "abort", nil
	}
	if control.state.Policy.PauseAfter > 0 && count >= control.state.Policy.PauseAfter {
		return "pause", nil
	}
	return "record", nil
}
func (control *Control) Snapshot() Snapshot {
	control.mu.Lock()
	defer control.mu.Unlock()
	state := control.state
	state.Signals = append([]Signal{}, state.Signals...)
	return state
}
