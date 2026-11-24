package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"rogue/internal/arsenal"
	"rogue/internal/domain"
	"rogue/internal/mission"
	"rogue/internal/operator"
	"rogue/internal/target"
)

func (harness *Harness) services(ctx context.Context, state *RunState, task mission.Task) context.Context {
	return arsenal.WithServices(ctx, arsenal.Services{
		Mission:func()any{return state.Control.Snapshot()},
		Surface:func()any{return surfaceResearch(state)},
		Chains:func()any{return chainResearch(state)},
		ValidateEvidence:func(ids []string,assertion string)(any,error){return validateEvidence(state,ids,assertion)},
		RunChild:func(operation context.Context,name string,args json.RawMessage)(*arsenal.Result,error){return harness.runChild(operation,state,task,name,args)},
		Candidates: func() any { return target.CandidateMatches(state.Targets.Snapshot()) },
		Evidence: func(ids []string) (any, error) {
			items := make([]contextObservation, 0, len(ids))
			for _, id := range ids {
				observation, err := state.Evidence.Observation(id)
				if err != nil {
					return nil, err
				}
				items = append(items, contextObservation{ID: observation.ID, TaskID: observation.TaskID, Tool: observation.Tool, Target: observation.Target, Success: observation.Success, Summary: observation.Summary, Error: observation.Error, Output: clip(string(observation.Output), 8192)})
			}
			return map[string]any{"observations": items, "credentials": state.Evidence.Credentials()}, nil
		},
		Credential: func(id, target string) (string, error) {
			credential, err := state.Evidence.CredentialSecret(id)
			if err != nil {
				return "", err
			}
			source, e1 := url.Parse(credential.TargetID)
			destination, e2 := url.Parse(target)
			if e1 != nil || e2 != nil || source.Scheme != destination.Scheme || source.Host != destination.Host {
				return "", errors.New("credential is bound to another origin")
			}
			return credential.Value, nil
		},
		Propose: func(proposal arsenal.TaskProposal) (any, error) { return harness.acceptProposal(state, task, proposal) },
	})
}

// The supervisor proposes; mission control validates. A model cannot create a
// new scope, grant approval, dispatch unsupported tools, or bypass dependencies.
func (harness *Harness) acceptProposal(state *RunState, supervisor mission.Task, proposal arsenal.TaskProposal) (any, error) {
	if supervisor.Archetype != domain.ArchCoordinator {
		return nil, errors.New("only the Coordinator can propose tasks")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	snapshot := state.Control.Snapshot()
	if snapshot.Status != mission.Active || len(snapshot.Tasks) >= 24 {
		return nil, errors.New("mission inactive or task capacity exhausted")
	}
	spending := state.Budget.Snapshot()
	if spending.InputTokens+spending.OutputTokens+spending.ReservedTokens >= harness.opts.MaxTokens {
		return nil, errors.New("mission budget exhausted")
	}
	role := domain.Archetype(proposal.Role)
	profile, found := operator.Profiles()[role]
	if !found || role == domain.ArchCoordinator || strings.TrimSpace(proposal.Title) == "" || len(proposal.Title) > 1024 {
		return nil, errors.New("invalid proposed role or title")
	}
	if len(proposal.EvidenceIDs) == 0 || len(proposal.EvidenceIDs) > 8 {
		return nil, errors.New("proposal requires 1–8 supporting observations")
	}
	if len(proposal.RequiredTools) > 8 || len(proposal.Target) > 2048 {
		return nil, errors.New("proposal exceeds tool or target limits")
	}
	dependencies := []string{supervisor.ID}
	for _, id := range proposal.EvidenceIDs {
		observation, err := state.Evidence.Observation(id)
		if err != nil || !observation.Success {
			return nil, errors.New("proposal references missing or unsuccessful evidence")
		}
		if !slices.Contains(dependencies, observation.TaskID) {
			dependencies = append(dependencies, observation.TaskID)
		}
	}
	if proposal.Target != "" {
		host := proposal.Target
		if parsed, err := url.Parse(proposal.Target); err == nil && parsed.Hostname() != "" {
			host = parsed.Hostname()
		}
		if !snapshot.Rules.AllowsHost(host) {
			return nil, errors.New("proposed target is outside mission scope")
		}
	}
	if (role == domain.ArchRecon || role == domain.ArchScanner) && proposal.Target == "" {
		return nil, errors.New("network assessment proposals require an explicit scoped target")
	}
	for _, name := range proposal.RequiredTools {
		tool := harness.reg.Get(name)
		if tool == nil || !slices.Contains(profile.ToolCats, tool.Category) || tool.LabOnly && !harness.opts.Lab {
			return nil, fmt.Errorf("tool %s is unsupported for proposed role", name)
		}
		if tool.Available != nil {
			if err := tool.Available(); err != nil {
				return nil, err
			}
		}
		if !tool.Internal && len(snapshot.Rules.AllowedTools) > 0 && !slices.Contains(snapshot.Rules.AllowedTools, name) {
			return nil, errors.New("proposed tool excluded by rules")
		}
	}
	title := strings.TrimSpace(proposal.Title) + " Target: " + proposal.Target + " Supporting observations: " + strings.Join(proposal.EvidenceIDs, ", ")
	for _, existing := range snapshot.Tasks {
		if existing.Archetype == role && existing.Title == title {
			return nil, errors.New("duplicate task proposal")
		}
	}
	accepted, err := state.Control.AddPrerequisite(proposal.BeforeTask, title, role, 80, dependencies...)
	if err != nil {
		return nil, err
	}
	if err = state.publish("control", "plan.accepted", accepted.ID, proposal.EvidenceIDs...); err != nil {
		return nil, err
	}
	return accepted, state.save()
}
