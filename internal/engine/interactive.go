package engine

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"rogue/internal/operator"
	"rogue/internal/opsec"
)

type ApprovalDecision int

const (
	ApprovalDeny ApprovalDecision = iota
	ApprovalOnce
	ApprovalMission
)

// ApprovalRequest carries the original exact action. Mission permission applies
// only to this actionKey, never to every invocation of a tool.
type ApprovalRequest struct {
	MissionID, Tool, Target string
	Arguments               json.RawMessage
}
type ApprovalHandler func(context.Context, ApprovalRequest) (ApprovalDecision, error)
type approvalHandlerKey struct{}

// WithApprovalHandler opts a single run into interactive decisions without
// changing Engine or the behavior of unattended API/CLI callers.
func WithApprovalHandler(ctx context.Context, handler ApprovalHandler) context.Context {
	return context.WithValue(ctx, approvalHandlerKey{}, handler)
}
func interactiveHandler(ctx context.Context) ApprovalHandler {
	handler, _ := ctx.Value(approvalHandlerKey{}).(ApprovalHandler)
	return handler
}

func (harness *Harness) actionApprover(ctx context.Context, state *RunState) func(string, json.RawMessage) error {
	return func(tool string, args json.RawMessage) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := state.consumeApproval(tool, args); err == nil {
			return nil
		}
		handler := interactiveHandler(ctx)
		if handler == nil {
			return errors.New("exact action approval missing, expired, or already used")
		}
		id := state.Control.Snapshot().ID
		target := ""
		var fields map[string]json.RawMessage
		if _, err := actionKey(tool, args); err != nil {
			return err
		}
		_ = json.Unmarshal(args, &fields)
		for _, key := range []string{"url", "host", "target", "path", "address"} {
			if json.Unmarshal(fields[key], &target) == nil && target != "" {
				break
			}
		}
		state.mu.Lock()
		state.approvalRequests++
		state.mu.Unlock()
		decision, err := func() (ApprovalDecision, error) {
			defer func() { state.mu.Lock(); state.approvalRequests--; state.mu.Unlock() }()
			return handler(ctx, ApprovalRequest{MissionID: id, Tool: tool, Target: target, Arguments: append(json.RawMessage(nil), args...)})
		}()
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if decision != ApprovalOnce && decision != ApprovalMission {
			return errors.New("exact action denied by operator")
		}
		if err = harness.ApproveTool(id, tool, args, time.Now().Add(59*time.Minute)); err != nil {
			return err
		}
		if decision == ApprovalMission {
			key, _ := actionKey(tool, args)
			state.mu.Lock()
			grant := state.approvals[key]
			grant.Reusable = true
			state.approvals[key] = grant
			state.mu.Unlock()
		}
		return state.consumeApproval(tool, args)
	}
}

// WithWarRoomPresets rebuilds an idle harness so the running engine's options
// are never mutated concurrently with workers.
func (harness *Harness) WithWarRoomPresets(profile, roe, team string) (Engine, error) {
	p, ok := opsec.LookupProfile(profile)
	if !ok {
		return nil, errors.New("unknown OPSEC profile")
	}
	if _, ok = opsec.LookupRoE(roe); !ok {
		return nil, errors.New("unknown RoE preset")
	}
	if _, ok = operator.LookupTeam(team); !ok {
		return nil, errors.New("unknown team")
	}
	if state := harness.LastRun(); state != nil {
		status := state.Control.Snapshot().Status
		if status == "active" || status == "paused" || status == "planning" {
			return nil, errors.New("finish the active mission before changing presets")
		}
	}
	opts := harness.opts
	opts.OPSECProfile, opts.RoEPreset, opts.Team = profile, roe, team
	opts.OPSEC = p.Policy()
	opts.Cooldown = p.Cooldown
	next := NewHarnessWithOptions(harness.provider, harness.reg, harness.models, harness.defModel, opts)
	next.last = harness.LastRun()
	return next, nil
}
