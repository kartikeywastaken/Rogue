package engine

import (
	"fmt"
	"strings"

	"rogue/internal/domain"
	"rogue/internal/mission"
)

const maxServiceFollowups = 4

// expandDiscovery derives work only from observed inventory, never a model's
// claimed discovery. The Scanner's main task becomes a barrier, so downstream
// reviews cannot race ahead of these additional assessments.
// Caller holds state.mu; the new graph and audit are saved with task completion.
func (harness *Harness) expandDiscovery(state *RunState, discovery mission.Task) error {
	var scanner mission.Task
	for _, task := range state.Control.Snapshot().Tasks {
		if task.Archetype == domain.ArchScanner && task.Status == mission.Pending {
			scanner = task
			break
		}
	}
	if scanner.ID == "" {
		return nil
	}
	tools := harness.reg.ToolDefsFor([]string{"recon", "web", "vuln"})
	if len(tools) == 0 {
		return nil
	}
	rules := state.Control.Snapshot().Rules
	added := 0
	for _, host := range state.Targets.Snapshot().Hosts {
		if !rules.AllowsHost(host.Name) {
			continue
		}
		for _, service := range host.Services {
			if added == maxServiceFollowups {
				return nil
			}
			if len(service.Evidence) == 0 || !rules.AllowsPort(service.Port) {
				continue
			}
			title := fmt.Sprintf("Assess observed service %s:%d/%s (%s %s %s). Supporting observations: %s. Perform only missing configuration or version checks; reuse existing results. Empty or negative results are completed evidence, not a reason to repeat a check. ExecutionFacts gives authoritative call counts. Look up CVE candidates only when a product/version is supported by evidence. Report applicability as unknown unless the required preconditions are demonstrated. Do not execute exploits or infer a vulnerability from an open port.", host.Name, service.Port, service.Protocol, service.Name, service.Product, service.Version, strings.Join(service.Evidence, ", "))
			task, err := state.Control.AddPrerequisite(scanner.ID, title, domain.ArchScanner, scanner.Priority+1, discovery.ID)
			if err != nil {
				return err
			}
			if err := state.publish("control", "plan.expanded", task.ID, service.Evidence...); err != nil {
				return err
			}
			added++
		}
	}
	return nil
}
