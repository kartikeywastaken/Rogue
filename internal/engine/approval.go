package engine

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"rogue/internal/comms"
	"rogue/internal/mission"
	"rogue/internal/opsec"
)

type Approval struct {
	ID, MissionID, Tool, ArgumentsHash string
	ExpiresAt                          time.Time
	Used                               bool
}

func actionKey(tool string, args json.RawMessage) (string, error) {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(args, &value); err != nil || value == nil {
		return "", errors.New("approval arguments must be a JSON object")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(append([]byte(tool+"\n"), canonical...))), nil
}

// ApproveTool grants one exact action for one live mission. Scope, role, schema,
// and exclusion checks still run at execution; a grant never widens those rules.
// Grants intentionally expire on restart. The encrypted comms log retains audit.
func (harness *Harness) ApproveTool(id, tool string, args json.RawMessage, expires time.Time) error {
	state, err := harness.activeRun(id)
	if err != nil {
		return err
	}
	if harness.reg.Get(tool) == nil {
		return errors.New("unknown tool")
	}
	if !expires.After(time.Now()) || expires.After(time.Now().Add(time.Hour)) {
		return errors.New("approval must expire within one hour")
	}
	key, err := actionKey(tool, args)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.approvals == nil {
		state.approvals = make(map[string]Approval)
	}
	grant := Approval{ID: key, MissionID: id, Tool: tool, ArgumentsHash: key, ExpiresAt: expires}
	data, _ := json.Marshal(grant)
	if _, err = state.Comms.Publish(comms.Message{From: "control", Topic: "approval.granted", Content: tool, Data: data}); err != nil {
		return err
	}
	if err = state.save(); err != nil {
		return err
	}
	state.approvals[key] = grant
	return nil
}

func (state *RunState) consumeApproval(tool string, args json.RawMessage) error {
	key, err := actionKey(tool, args)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	grant, found := state.approvals[key]
	if !found || grant.Used || !time.Now().Before(grant.ExpiresAt) {
		return errors.New("exact action approval missing, expired, or already used")
	}
	grant.Used = true
	state.approvals[key] = grant
	data, _ := json.Marshal(grant)
	if _, err = state.Comms.Publish(comms.Message{From: "control", Topic: "approval.consumed", Content: tool, Data: data}); err != nil {
		return err
	}
	return state.save()
}

func (state *RunState) approvedTools(names []string) []string {
	state.mu.Lock()
	defer state.mu.Unlock()
	result := append([]string{}, names...)
	for _, grant := range state.approvals {
		if !grant.Used && time.Now().Before(grant.ExpiresAt) && !slices.Contains(result, grant.Tool) {
			result = append(result, grant.Tool)
		}
	}
	return result
}

// RecordDetection accepts an explicit observer signal. A failed connection is
// not automatically called detection. Signals and IOCs remain auditable even
// when the caller selects a zero threshold (record only).
func (harness *Harness) RecordDetection(id, source, indicator string, threshold int) error {
	if source == "" || indicator == "" || threshold < 0 {
		return errors.New("source, indicator and nonnegative threshold required")
	}
	state, err := harness.activeRun(id)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if err = state.signal(opsec.Signal{Source: source, Kind: "observer_report", Indicator: indicator}); err != nil {
		return err
	}
	state.detections++
	if threshold > 0 && state.detections >= threshold {
		if state.Control.Snapshot().Status == mission.Active {
			err = state.Control.Pause()
		}
		if err != nil {
			return errors.Join(err, state.save())
		}
		if err = state.publish("control", "opsec.paused", "explicit detection threshold reached"); err != nil {
			return err
		}
	}
	return state.save()
}
