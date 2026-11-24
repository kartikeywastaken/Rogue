package engine

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"rogue/internal/agent"
	"rogue/internal/arsenal"
	"rogue/internal/domain"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/operator"
)

// ExecuteTool is a human-issued exact action using the real policy, dispatcher,
// vault and encrypted storage. It does not require or impersonate an LLM.
func (harness *Harness) ExecuteTool(parent context.Context, name string, args json.RawMessage, role domain.Archetype, mode Mode) (report Report, failure error) {
	profile, found := operator.Profiles()[role]
	if !found {
		return report, errors.New("unknown operator")
	}
	state, cleanup, err := harness.prepare(Request{Prompt: "Human-issued tool action: " + name, Mode: mode})
	if err != nil {
		return report, err
	}
	defer cleanup()
	id := state.Control.Snapshot().ID
	defer func() {
		state.mu.Lock()
		status := state.Control.Snapshot().Status
		if status == mission.Planning || status == mission.Active || status == mission.Paused {
			reason := "manual action ended before mission completion"
			if failure != nil {
				reason = failure.Error()
			}
			if parent.Err() != nil {
				_ = state.Control.Abort(reason)
			} else {
				_ = state.Control.Fail(reason)
			}
			state.Comms.Close()
			failure = errors.Join(failure, state.save())
		}
		state.mu.Unlock()
		loaded, err := harness.Report(id)
		report = loaded
		failure = errors.Join(failure, err)
	}()
	ctx, cancel := context.WithTimeout(parent, harness.opts.Timeout)
	defer cancel()
	if err = state.Comms.Join(profile.Callsign); err != nil {
		return report, err
	}
	if err = state.Control.Start(); err != nil {
		return report, err
	}
	if _, err = state.Control.AddTask("Execute "+name, role, 100); err != nil {
		return report, err
	}
	task, ready := state.Control.Claim(role, profile.Callsign)
	if !ready {
		return report, errors.New("manual task unavailable")
	}
	if err = state.Cell.Begin(role, task.ID); err != nil {
		return report, err
	}
	operation, finish, err := state.Cell.Execute(ctx, role)
	if err != nil {
		return report, err
	}
	defer finish()
	ctx = operation
	defer func() {
		state.Cell.Finish(role, failure)
		state.mu.Lock()
		failure = errors.Join(failure, state.save())
		state.mu.Unlock()
	}()
	call := llm.ToolCall{ID: domain.ID(), Type: "function", Function: llm.FuncCall{Name: name, Arguments: string(args)}}
	// The explicit command approves only these arguments, never wider scope.
	if err = harness.ApproveTool(id, name, args, time.Now().Add(time.Minute)); err != nil {
		return report, err
	}
	ctx = arsenal.WithPolicy(ctx, arsenal.Policy{Lab: harness.opts.Lab, Mode: mode.String(), Rules: harness.opts.Rules, Categories: profile.ToolCats, Approve: state.consumeApproval})
	ctx = harness.services(ctx, state, task)
	if err = state.recordIntent(task, profile, call); err != nil {
		return report, err
	}
	start := time.Now().UTC()
	result, err := harness.reg.Exec(ctx, name, args)
	if result == nil {
		message := "tool returned no result"
		if err != nil {
			message = err.Error()
		}
		result = &arsenal.Result{Success: false, Error: message, Summary: message}
	}
	if recordError := state.recordResult(task, profile, agent.Execution{Call: call, Result: result, StartedAt: start}); recordError != nil {
		err = errors.Join(err, recordError)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if err != nil || !result.Success {
		if err == nil {
			message := result.Error
			if message == "" {
				message = "tool reported unsuccessful completion"
			}
			err = errors.New(message)
		}
		if parent.Err() != nil {
			_ = state.Control.Abort(err.Error())
		} else {
			_ = state.Control.FailTask(task.ID, err.Error())
			_ = state.Control.Fail(err.Error())
		}
	} else {
		err = state.Control.CompleteTask(task.ID, result.Summary)
		if err == nil {
			err = state.Control.Finish()
		}
	}
	state.Comms.Close()
	return report, errors.Join(err, state.save())
}
