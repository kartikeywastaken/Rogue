package engine

import (
	"encoding/json"
	"errors"
	"strings"
)

// ToolTrace is a local operator inspector, not a public report endpoint. It
// returns complete recorded JSON while retaining the tool's secret redactions.
func (harness *Harness) ToolTrace(id, callID string) (json.RawMessage, error) {
	state := harness.LastRun()
	if state == nil || state.Control.Snapshot().ID != id {
		return nil, errors.New("tool trace is unavailable for this mission")
	}
	parts := strings.SplitN(callID, "/", 2)
	taskID := ""
	if len(parts) == 2 {
		taskID, callID = parts[0], parts[1]
	}
	for _, obs := range state.Evidence.Observations() {
		if obs.ToolCallID != callID || taskID != "" && obs.TaskID != taskID {
			continue
		}
		if tool := harness.reg.Get(obs.Tool); tool != nil {
			var args map[string]json.RawMessage
			if json.Unmarshal(obs.Input, &args) == nil {
				for _, name := range tool.SensitiveArgs {
					if _, ok := args[name]; ok {
						args[name] = json.RawMessage(`"[redacted]"`)
					}
				}
				obs.Input, _ = json.Marshal(args)
			}
		}
		obs.Artifact = nil
		return json.MarshalIndent(obs, "", "  ")
	}
	return nil, errors.New("tool output is not recorded yet")
}
