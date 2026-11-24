package operator

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"rogue/internal/domain"
)

// Agent describes a worker, not a separate model or process. All workers share
// the mission budget and receive only tools allowed by their profile.
type Agent struct {
	ID                string
	Profile           Profile
	State             domain.OperatorState
	TaskID            string
	Completed, Failed int
	ReadyAt           time.Time
	LastError         string
	Risk              float64
	BurnReason        string
}

type Cell struct {
	mu               sync.Mutex
	agents           map[domain.Archetype]Agent
	capacity, active int
	cooldown         time.Duration
	cancels          map[domain.Archetype]context.CancelCauseFunc
}

func NewCell(capacity int, cooldown time.Duration) *Cell {
	if capacity < 1 {
		capacity = 2
	}
	if capacity > 8 {
		capacity = 8
	}
	cell := &Cell{agents: make(map[domain.Archetype]Agent), capacity: capacity, cooldown: cooldown, cancels: make(map[domain.Archetype]context.CancelCauseFunc)}
	for role, profile := range Profiles() {
		cell.agents[role] = Agent{ID: profile.Callsign, Profile: profile, State: domain.StateIdle}
	}
	return cell
}

func (cell *Cell) Begin(role domain.Archetype, taskID string) error {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	agent, found := cell.agents[role]
	if !found || cell.active >= cell.capacity || agent.TaskID != "" || agent.State == domain.StateBurned || time.Now().Before(agent.ReadyAt) {
		return errors.New("operator unavailable or cell at capacity")
	}
	agent.TaskID, agent.State = taskID, domain.StateTasked
	cell.agents[role] = agent
	cell.active++
	return nil
}

func (cell *Cell) Execute(parent context.Context, role domain.Archetype) (context.Context, func(), error) {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	agent, found := cell.agents[role]
	if !found || agent.State != domain.StateTasked {
		return nil, nil, errors.New("operator has no assigned task")
	}
	ctx, cancel := context.WithCancelCause(parent)
	cell.cancels[role] = cancel
	agent.State = domain.StateExecuting
	cell.agents[role] = agent
	return ctx, func() { cancel(context.Canceled) }, nil
}

func (cell *Cell) Burn(role domain.Archetype, reason string) error {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	agent, found := cell.agents[role]
	if !found || reason == "" {
		return errors.New("operator and burn reason required")
	}
	agent.State = domain.StateBurned
	agent.BurnReason = reason
	cell.agents[role] = agent
	if cancel := cell.cancels[role]; cancel != nil {
		cancel(errors.New("operator burned: " + reason))
	}
	return nil
}

func (cell *Cell) Finish(role domain.Archetype, failure error) {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	agent := cell.agents[role]
	if agent.TaskID == "" {
		return
	}
	agent.TaskID = ""
	if agent.State != domain.StateBurned {
		agent.State = domain.StateCooldown
	}
	delete(cell.cancels, role)
	agent.ReadyAt = time.Now().Add(cell.cooldown)
	if failure == nil {
		agent.Completed++
	} else {
		agent.Failed++
		agent.LastError = failure.Error()
		// This is a failure-risk heuristic from the paper, not measured detection.
		agent.Risk = min(1, float64(agent.Failed)/10)
		if agent.Risk >= 0.7 {
			agent.State = domain.StateBurned
			agent.BurnReason = "failure-risk threshold reached"
		}
	}
	cell.agents[role] = agent
	cell.active--
}

func (cell *Cell) Snapshot() []Agent {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	result := make([]Agent, 0, len(cell.agents))
	for _, agent := range cell.agents {
		if agent.State == domain.StateCooldown && !time.Now().Before(agent.ReadyAt) {
			agent.State = domain.StateIdle
		}
		agent.Profile.ToolCats = append([]string{}, agent.Profile.ToolCats...)
		result = append(result, agent)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
