package engine

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"rogue/internal/comms"
	"rogue/internal/domain"
	"rogue/internal/evidence"
	"rogue/internal/mission"
	"rogue/internal/operator"
)

type contextObservation struct {
	ID, TaskID, Tool, Target string
	Success                  bool
	Summary, Error, Output   string
}

type sharedContext struct {
	ExecutionFacts struct {
		CallsAttempted       int
		ObservationsRecorded int
		ToolCounts           map[string]int
	}
	Rules                          mission.Rules
	Observations                   []contextObservation
	Findings                       []domain.Finding
	Credentials                    []domain.Credential
	Tasks                          []mission.Task
	UnverifiedPredecessorSummaries map[string]string
	Messages                       []comms.Message
	OmittedObservations            int
}

// Prefer direct handoffs and cited evidence over recency. An older finding's
// supporting observation should survive an unrelated burst of tool activity.
func relevantObservations(task mission.Task, tasks []mission.Task, observations []evidence.Observation, findings []domain.Finding) []evidence.Observation {
	ancestors, needed := make(map[string]bool), make(map[string]bool)
	for _, id := range task.Dependencies {
		ancestors[id] = true
	}
	for index := len(tasks) - 1; index >= 0; index-- {
		if ancestors[tasks[index].ID] {
			for _, id := range tasks[index].Dependencies {
				ancestors[id] = true
			}
		}
	}
	for _, finding := range findings {
		for _, id := range finding.Evidence {
			needed[id] = true
		}
	}
	score := func(item evidence.Observation) int {
		value := 0
		if ancestors[item.TaskID] {
			value += 2
		}
		if slices.Contains(task.Dependencies, item.TaskID) {
			value += 4
		}
		if item.Target != "" && strings.Contains(strings.ToLower(task.Title), strings.ToLower(item.Target)) {
			value += 8
		}
		if needed[item.ID] || strings.Contains(task.Title, item.ID) {
			value += 16
		}
		return value
	}
	sort.SliceStable(observations, func(i, j int) bool {
		left, right := score(observations[i]), score(observations[j])
		if left != right {
			return left > right
		}
		return observations[i].StartedAt.After(observations[j].StartedAt)
	})
	if len(observations) > 20 {
		observations = observations[:20]
	}
	return observations
}

func (harness *Harness) taskContext(state *RunState, task mission.Task, profile operator.Profile) string {
	state.mu.Lock()
	defer state.mu.Unlock()
	mission := state.Control.Snapshot()
	observations, findings := state.Evidence.Observations(), state.Evidence.Findings()
	context := sharedContext{Rules: mission.Rules, UnverifiedPredecessorSummaries: make(map[string]string)}
	context.ExecutionFacts.CallsAttempted = state.toolCalls
	context.ExecutionFacts.ObservationsRecorded = len(observations)
	context.ExecutionFacts.ToolCounts = make(map[string]int)
	context.Credentials = state.Evidence.Credentials()
	if len(context.Credentials) > 8 {
		context.Credentials = context.Credentials[:8]
	}
	for _, planned := range mission.Tasks {
		planned.Title = clip(planned.Title, 256)
		planned.Result = ""
		planned.Error = ""
		context.Tasks = append(context.Tasks, planned)
	}
	for _, observation := range observations {
		context.ExecutionFacts.ToolCounts[observation.Tool]++
	}
	selected := relevantObservations(task, mission.Tasks, observations, findings)
	remaining := harness.opts.ContextBytes
	for _, observation := range selected {
		// Excerpts remain strings with an explicit truncation marker, never
		// partially parsed JSON that might be mistaken for a complete result.
		item := contextObservation{ID: observation.ID, TaskID: observation.TaskID, Tool: observation.Tool, Target: clip(observation.Target, 512), Success: observation.Success, Summary: clip(observation.Summary, 512), Error: clip(observation.Error, 256), Output: clip(string(observation.Output), 2048)}
		encoded, _ := json.Marshal(item)
		if len(encoded) > remaining {
			continue
		}
		remaining -= len(encoded)
		context.Observations = append(context.Observations, item)
	}
	context.OmittedObservations = len(observations) - len(context.Observations)
	for _, prior := range mission.Tasks {
		if slices.Contains(task.Dependencies, prior.ID) {
			context.UnverifiedPredecessorSummaries[prior.ID] = clip(prior.Result, 2048)
		}
	}
	for _, finding := range findings {
		if len(context.Findings) == 8 {
			break
		}
		finding.Title = clip(finding.Title, 256)
		finding.Description = clip(finding.Description, 1024)
		finding.Remediation = clip(finding.Remediation, 512)
		context.Findings = append(context.Findings, finding)
	}
	history := state.Comms.History(profile.Callsign)
	if len(history) > 12 {
		history = history[len(history)-12:]
	}
	for index := range history {
		history[index].Data = nil
		history[index].Content = clip(history[index].Content, 512)
	}
	context.Messages = history
	data, err := json.Marshal(context)
	// Fit the whole envelope, not just observations. Remove lower-priority
	// messages before evidence; model summaries are never a substitute for it.
	for err == nil && len(data) > harness.opts.ContextBytes {
		switch {
		case len(context.Tasks) > 0:
			context.Tasks = context.Tasks[:len(context.Tasks)-1]
		case len(context.Messages) > 0:
			context.Messages = context.Messages[1:]
		case len(context.UnverifiedPredecessorSummaries) > 0:
			for id := range context.UnverifiedPredecessorSummaries {
				delete(context.UnverifiedPredecessorSummaries, id)
			}
		case len(context.Findings) > 0:
			context.Findings = context.Findings[:len(context.Findings)-1]
		case len(context.Observations) > 0:
			context.Observations = context.Observations[:len(context.Observations)-1]
			context.OmittedObservations++
		default:
			return "Mission objective: " + mission.Objective + "\nAssigned task: " + task.Title + "\nShared context exceeds the configured limit; no evidence supplied."
		}
		data, err = json.Marshal(context)
	}
	if err != nil {
		return "Mission objective: " + mission.Objective + "\nAssigned task: " + task.Title + "\nShared context unavailable: " + err.Error()
	}
	return "Mission objective: " + mission.Objective + "\nAssigned task: " + task.Title + "\nShared context (ranked and bounded; omitted observations remain in the vault):\n" + string(data)
}
