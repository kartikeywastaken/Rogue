package engine

import (
	"encoding/json"
	"errors"
	"fmt"

	"rogue/internal/domain"
	"rogue/internal/evidence"
	"rogue/internal/mission"
	"rogue/internal/opsec"
)

func (state *RunState) signal(signal opsec.Signal) error {
	action, err := state.OPSEC.Record(signal)
	if err != nil {
		return err
	}
	var references []string
	if signal.ObservationID != "" {
		references = append(references, signal.ObservationID)
	}
	if err = state.publish("control", "opsec.signal", signal.Kind+": "+signal.Indicator, references...); err != nil {
		return err
	}
	switch action {
	case "pause":
		if state.Control.Snapshot().Status == mission.Active {
			err = state.Control.Pause()
		}
	case "abort":
		err = state.Control.Abort("OPSEC signal threshold reached")
	}
	return err
}

// A rate-limit response is an observed signal. An HTTP 403 or failed login
// alone does not establish that a monitoring system detected the assessment.
func (state *RunState) observeSignals(observation evidence.Observation) error {
	var result struct {
		Data struct {
			Status     int `json:"status"`
			StatusCode int `json:"status_code"`
		}
	}
	if json.Unmarshal(observation.Output, &result) != nil {
		return nil
	}
	if result.Data.Status != 429 && result.Data.StatusCode != 429 {
		return nil
	}
	return state.signal(opsec.Signal{Operator: observation.OperatorID, Kind: "rate_limit", Source: observation.Tool, Indicator: observation.Target, ObservationID: observation.ID})
}

func (harness *Harness) BurnOperator(id string, role domain.Archetype, reason string) error {
	state, err := harness.activeRun(id)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if err = state.Cell.Burn(role, reason); err != nil {
		return err
	}
	return errors.Join(state.publish("control", "operator.burned", fmt.Sprintf("%s: %s", role, reason)), state.save())
}
