package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"rogue/internal/agent"
	"rogue/internal/comms"
	"rogue/internal/domain"
	"rogue/internal/evidence"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/operator"
	"rogue/internal/opsec"
	"rogue/internal/storage"
	"rogue/internal/target"
)

// RunState groups the services owned by one mission. The mutex covers changes
// that must appear together in a durable checkpoint, such as a finding and its
// supporting tool observation.
type RunState struct {
	Control    *mission.Control
	Evidence   *evidence.Vault
	Comms      *comms.Channel
	Targets    *target.Environment
	Budget     *llm.Budget
	Cell       *operator.Cell
	OPSEC      *opsec.Control
	toolCalls  int
	approvals  map[string]Approval
	detections int
	usage      Usage
	mu         sync.Mutex
	store      *storage.Store
}

func (state *RunState) save() error {
	if state.store == nil {
		return nil
	}
	checkpoint := storage.Checkpoint{
		Mission: state.Control.Snapshot(), Evidence: state.Evidence.PrivateSnapshot(),
		Comms: state.Comms.Snapshot(), Targets: state.Targets.Snapshot(), Spending: state.Budget.Snapshot(),
	}
	if state.Cell != nil {
		checkpoint.Operators = state.Cell.Snapshot()
	}
	if state.OPSEC != nil {
		checkpoint.OPSEC = state.OPSEC.Snapshot()
	}
	return state.store.Save(checkpoint)
}

func (state *RunState) publish(sender, topic, content string, references ...string) error {
	_, err := state.Comms.Publish(comms.Message{From: sender, Topic: topic, Content: content, EvidenceIDs: references})
	return err
}

func toolTarget(call llm.ToolCall) string {
	var arguments map[string]json.RawMessage
	if json.Unmarshal([]byte(call.Function.Arguments), &arguments) != nil {
		return ""
	}
	for _, name := range []string{"host", "url", "cve_id", "keyword"} {
		var value string
		if json.Unmarshal(arguments[name], &value) == nil && value != "" {
			return value
		}
	}
	return ""
}

func (state *RunState) recordIntent(task mission.Task, profile operator.Profile, call llm.ToolCall) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	data, err := json.Marshal(struct {
		TaskID string
		Call   llm.ToolCall
	}{task.ID, call})
	if err != nil {
		return err
	}
	_, err = state.Comms.Publish(comms.Message{From: profile.Callsign, Topic: "tool.started", Content: call.Function.Name + " [" + call.ID + "]", Data: data})
	if err != nil {
		return err
	}
	return state.save()
}

func (state *RunState) recordResult(task mission.Task, profile operator.Profile, execution agent.Execution) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	output, err := json.Marshal(execution.Result)
	if err != nil {
		return err
	}
	observation, err := state.Evidence.Record(evidence.Observation{
		MissionID: task.MissionID, TaskID: task.ID, OperatorID: profile.Callsign,
		ToolCallID: execution.Call.ID, Tool: execution.Call.Function.Name, Target: toolTarget(execution.Call),
		Input: json.RawMessage(execution.Call.Function.Arguments), Output: output,
		Success: execution.Result.Success, Summary: execution.Result.Summary, Error: execution.Result.Error,
		StartedAt: execution.StartedAt, Duration: execution.Result.Dur,
		Artifact: execution.Result.Artifact, ArtifactType: execution.Result.ArtifactType,
	})
	if err != nil {
		return err
	}
	if err := state.publish(profile.Callsign, "tool.observed", execution.Result.Summary, observation.ID); err != nil {
		return err
	}
	if execution.Result.Success && len(execution.Result.Credentials) > 0 {
		var ids []string
		for _, credential := range execution.Result.Credentials {
			credential.MissionID = task.MissionID
			credential.TargetID = observation.Target
			credential.Source = observation.ID
			saved, err := state.Evidence.AddCredential(credential)
			if err != nil {
				return err
			}
			ids = append(ids, saved.ID)
			if err = state.publish(profile.Callsign, "credential.captured", saved.ID, observation.ID); err != nil {
				return err
			}
		}
		data, ok := execution.Result.Data.(map[string]any)
		if !ok {
			data = map[string]any{"result": execution.Result.Data}
		}
		data["credential_ids"] = ids
		execution.Result.Data = data
	}
	var findings []domain.Finding
	if execution.Result.Success {
		for _, finding := range execution.Result.Findings {
			finding.MissionID = task.MissionID
			finding.OperatorID = profile.Callsign
			finding.TargetID = observation.Target
			finding.Evidence = []string{observation.ID}
			saved, err := state.Evidence.AddFinding(finding)
			if err != nil {
				return err
			}
			findings = append(findings, saved)
			if err := state.publish(profile.Callsign, "finding.added", saved.Title, observation.ID); err != nil {
				return err
			}
		}
	}
	if err := state.Targets.Apply(observation, findings); err != nil {
		return err
	}
	if err := state.observeSignals(observation); err != nil {
		return err
	}
	return state.save()
}

func (harness *Harness) activeRun(id string) (*RunState, error) {
	harness.mu.RLock()
	defer harness.mu.RUnlock()
	state := harness.runs[id]
	if state == nil {
		return nil, fmt.Errorf("mission %s is not active in this process", id)
	}
	return state, nil
}

func (harness *Harness) PauseMission(id string) error { return harness.changeMission(id, "pause", "") }
func (harness *Harness) ResumeMission(id string) error {
	return harness.changeMission(id, "resume", "")
}
func (harness *Harness) AbortMission(id, reason string) error {
	return harness.changeMission(id, "abort", reason)
}

func (harness *Harness) changeMission(id, action, reason string) error {
	state, err := harness.activeRun(id)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	switch action {
	case "pause":
		err = state.Control.Pause()
	case "resume":
		err = state.Control.Resume()
	case "abort":
		err = state.Control.Abort(reason)
	default:
		err = errors.New("unknown mission action")
	}
	if err != nil {
		return err
	}
	messageError := state.publish("control", "mission."+action, reason)
	return errors.Join(messageError, state.save())
}

// Reports expose redacted credentials and observation metadata. Detailed raw
// traces remain inside the encrypted checkpoint instead of appearing by default.
type Report struct {
	OPSEC     opsec.Snapshot
	Operators []operator.Agent
	Analysis  Analysis
	Mission   mission.Mission
	Evidence  evidence.PublicSnapshot
	Targets   target.Snapshot
	Spending  llm.Spending
	Messages  []comms.Message
}

func (harness *Harness) Report(id string) (report Report, failure error) {
	var observations []evidence.Observation
	defer func() {
		if failure == nil {
			// Derive access paths from the protected trace, then return only the
			// redacted report. Public observation payloads intentionally stay nil.
			input := report
			input.Evidence.Observations = observations
			report.Analysis = Analyze(input)
		}
	}()
	if state, err := harness.activeRun(id); err == nil {
		state.mu.Lock()
		defer state.mu.Unlock()
		observations = state.Evidence.Observations()
		return Report{OPSEC: state.OPSEC.Snapshot(), Operators: state.Cell.Snapshot(), Mission: state.Control.Snapshot(), Evidence: state.Evidence.PublicSnapshot(), Targets: state.Targets.Snapshot(), Spending: state.Budget.Snapshot(), Messages: publicMessages(state.Comms.History(""))}, nil
	}
	if harness.opts.Store == nil {
		return Report{}, errors.New("durable storage is not configured")
	}
	checkpoint, err := harness.opts.Store.Load(id)
	if err != nil {
		return Report{}, err
	}
	vault, err := evidence.Restore(checkpoint.Evidence)
	if err != nil {
		return Report{}, err
	}
	observations = vault.Observations()
	return Report{OPSEC: checkpoint.OPSEC, Operators: checkpoint.Operators, Mission: checkpoint.Mission, Evidence: vault.PublicSnapshot(), Targets: checkpoint.Targets, Spending: checkpoint.Spending, Messages: publicMessages(checkpoint.Comms.History)}, nil
}

func publicMessages(messages []comms.Message) []comms.Message {
	for index := range messages {
		messages[index].Data = nil
	}
	return messages
}

func (harness *Harness) ReviewTarget(id, name, observationID, field string, acceptObserved bool) error {
	state, err := harness.activeRun(id)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.Targets.ReviewConflict(name, observationID, field, acceptObserved); err != nil {
		return err
	}
	messageError := state.publish("control", "target.reviewed", name, observationID)
	return errors.Join(messageError, state.save())
}
