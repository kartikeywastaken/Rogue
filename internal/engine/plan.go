package engine

import (
	"fmt"
	"rogue/internal/domain"
	"rogue/internal/mission"
	"rogue/internal/operator"
)

// OpGeneral uses a fixed, reviewable dependency graph. Model-written prose
// cannot silently add tasks, widen scope, or enable an unsupported capability.
type PlannedTask struct {
	Role         domain.Archetype
	Title        string
	Dependencies []int
}

func AssessmentPlan() []PlannedTask {
	return []PlannedTask{
		{domain.ArchCoordinator, "Review the objective, scope, tool capabilities and constraints. Identify unsupported requests and assessment priorities. Do not claim to execute specialist actions.", nil},
		{domain.ArchRecon, "Discover scoped assets and exposed services. Record real observations for the Scanner. Avoid duplicating existing observations.", []int{0}},
		{domain.ArchScanner, "Assess services discovered by Recon. Use TLS, headers and technology checks where relevant. Look up product/version CVE candidates; distinguish references from demonstrated weaknesses.", []int{1}},
		{domain.ArchCoordinator, "Supervise the completed assessment. Use evidence_get for missing details. If additional work is justified by successful observations, use propose_task to insert a scoped task before the pending Analyst; specify required tools and evidence IDs. Do not propose duplicates, change rules, or assert that a proposal itself executed an action. Otherwise conclude without adding work.", []int{2}},
		{domain.ArchExploiter, "Assess Scanner evidence and CVE preconditions. Approved loopback lab probes may gather reflection or database-error evidence. They do not establish exploitation. Without explicit lab approvals, limit conclusions to observed facts and unsupported hypotheses.", []int{3}},
		{domain.ArchInfiltrator, "Assess access-control evidence. With explicit lab approval and a captured lab credential, session_check may verify one endpoint response. No privilege escalation or lateral movement implementation is supplied. Report unmet preconditions explicitly.", []int{3}},
		{domain.ArchExfiltrator, "Assess observed data exposure. Approved exposure_check may collect a bounded loopback lab response into the protected vault and scan for potential secrets. No external data transfer is supplied. Do not claim exfiltration from a local read.", []int{3}},
		{domain.ArchGhost, "Assess persistence and cleanup risks. Approved cleanup_verify checks whether an explicit marker remains in a lab endpoint. It does not deploy persistence or perform cleanup. Without a supplied marker, review evidence and state the missing preconditions.", []int{3}},
		{domain.ArchAnalyst, "Produce executive and technical conclusions, evidence IDs, uncertainties, and remediation. Task summaries are unverified model text; ground factual claims in successful observations and ExecutionFacts. Never infer exploitation from service discovery or CVE lookup.", []int{4, 5, 6, 7}},
	}
}

func installPlan(control *mission.Control, plan []PlannedTask) error {
	if len(plan) == 0 || len(plan) > 32 {
		return fmt.Errorf("plan must contain 1–32 tasks")
	}
	ids := make([]string, 0, len(plan))
	profiles := operator.Profiles()
	for index, item := range plan {
		if _, found := profiles[item.Role]; !found {
			return fmt.Errorf("unknown role %q", item.Role)
		}
		dependencies := make([]string, 0, len(item.Dependencies))
		for _, dependency := range item.Dependencies {
			if dependency < 0 || dependency >= index {
				return fmt.Errorf("plan dependencies must reference earlier tasks")
			}
			dependencies = append(dependencies, ids[dependency])
		}
		task, err := control.AddTask(item.Title, item.Role, 100-index, dependencies...)
		if err != nil {
			return err
		}
		ids = append(ids, task.ID)
	}
	return nil
}
