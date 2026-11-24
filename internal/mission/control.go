// Package mission owns mission lifecycle and dependency-aware task dispatch.
package mission

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"rogue/internal/domain"
)

type Status string

const (
	Planning  Status = "planning"
	Active    Status = "active"
	Paused    Status = "paused"
	Completed Status = "completed"
	Failed    Status = "failed"
	Aborted   Status = "aborted"
)

type TaskStatus string

const (
	Pending       TaskStatus = "pending"
	Running       TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	Blocked       TaskStatus = "blocked"
	Cancelled     TaskStatus = "cancelled"
)

type Task struct {
	ID, MissionID, Title, OperatorID string
	Archetype                        domain.Archetype
	Phase                            domain.KillChainPhase
	Priority                         int
	Dependencies                     []string
	Status                           TaskStatus
	Result, Error                    string
	CreatedAt, StartedAt, FinishedAt time.Time
}
type Mission struct {
	ID, Objective                             string
	Status                                    Status
	Phase                                     domain.KillChainPhase
	Phases                                    []domain.KillChainPhase
	Rules                                     Rules
	CreatedAt, StartedAt, FinishedAt          time.Time
	Reason                                    string
	Tasks                                     []Task
	Progress                                  float64
	CompletedTasks, FailedTasks, BlockedTasks int
}

// Control serializes claims and state transitions. Snapshots never expose owned slices.
type Control struct {
	mu      sync.RWMutex
	mission Mission
	tasks   []Task
	runtime *Runtime
}

func New(id, objective string, rules Rules) (*Control, error) {
	if strings.TrimSpace(objective) == "" {
		return nil, errors.New("mission objective required")
	}
	if err := rules.Validate(); err != nil {
		return nil, err
	}
	if id == "" {
		id = domain.ID()
	}
	return &Control{runtime: NewRuntime(), mission: Mission{ID: id, Objective: objective, Rules: rules.clone(), Status: Planning, Phase: domain.PhaseRecon, Phases: []domain.KillChainPhase{domain.PhaseRecon}, CreatedAt: time.Now().UTC()}}, nil
}

func cloneTask(t Task) Task { t.Dependencies = slices.Clone(t.Dependencies); return t }
func (c *Control) Snapshot() Mission {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m := c.mission
	m.Rules = m.Rules.clone()
	m.Phases = slices.Clone(m.Phases)
	m.Tasks = make([]Task, len(c.tasks))
	for i, t := range c.tasks {
		m.Tasks[i] = cloneTask(t)
		switch t.Status {
		case TaskCompleted:
			m.CompletedTasks++
		case TaskFailed:
			m.FailedTasks++
		case Blocked:
			m.BlockedTasks++
		}
	}
	if len(c.tasks) > 0 {
		m.Progress = 100 * float64(m.CompletedTasks) / float64(len(c.tasks))
	}
	return m
}

func (c *Control) Runtime() *Runtime { return c.runtime }

func (c *Control) Start() error  { return c.transition(Planning, Active) }
func (c *Control) Pause() error  { return c.transition(Active, Paused) }
func (c *Control) Resume() error { return c.transition(Paused, Active) }
func (c *Control) transition(expected, next Status) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.mission.Status
	if s != expected {
		return fmt.Errorf("mission: cannot transition %s to %s", s, next)
	}
	c.mission.Status = next
	if next == Paused {
		c.runtime.Pause()
	}
	if expected == Paused && next == Active {
		c.runtime.Resume()
	}
	if c.mission.StartedAt.IsZero() {
		c.mission.StartedAt = time.Now().UTC()
	}
	return nil
}

// Dependencies must already exist, making cycles impossible by construction.
func (c *Control) AddTask(title string, role domain.Archetype, priority int, deps ...string) (Task, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addTask(c.mission.Phase, title, role, priority, deps...)
}

func (c *Control) AddTaskInPhase(phase domain.KillChainPhase, title string, role domain.Archetype, priority int, deps ...string) (Task, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addTask(phase, title, role, priority, deps...)
}

// AddPrerequisite inserts evidence-driven work before a task that has not
// started. Dependencies must precede that task already; this preserves the
// topological order used by recovery and makes cycles impossible.
func (c *Control) AddPrerequisite(id, title string, role domain.Archetype, priority int, deps ...string) (Task, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.index(id)
	if index < 0 || c.tasks[index].Status != Pending {
		return Task{}, errors.New("mission: prerequisite destination must be pending")
	}
	for _, dependency := range deps {
		position := c.index(dependency)
		if position < 0 || position >= index {
			return Task{}, errors.New("mission: prerequisite must depend on earlier work")
		}
	}
	task, err := c.addTask(c.tasks[index].Phase, title, role, priority, deps...)
	if err != nil {
		return Task{}, err
	}
	// addTask appended a validated task. Move it before the destination, then
	// make the destination wait for it. Existing task IDs never change.
	copy(c.tasks[index+1:], c.tasks[index:len(c.tasks)-1])
	c.tasks[index] = task
	c.tasks[index+1].Dependencies = append(c.tasks[index+1].Dependencies, task.ID)
	c.blockDependents()
	return cloneTask(task), nil
}

func (c *Control) addTask(phase domain.KillChainPhase, title string, role domain.Archetype, priority int, deps ...string) (Task, error) {
	if c.mission.Status != Planning && c.mission.Status != Active && c.mission.Status != Paused {
		return Task{}, errors.New("mission: cannot add task after termination")
	}
	if strings.TrimSpace(title) == "" || !validRole(role) {
		return Task{}, errors.New("mission: invalid task title or archetype")
	}
	phaseIndex := slices.Index(c.mission.Phases, phase)
	if phaseIndex < slices.Index(c.mission.Phases, c.mission.Phase) || phaseIndex < 0 {
		return Task{}, errors.New("mission: invalid or already finished task phase")
	}
	for _, dep := range deps {
		i := c.index(dep)
		if i < 0 {
			return Task{}, fmt.Errorf("mission: unknown dependency %q", dep)
		}
		if slices.Index(c.mission.Phases, c.tasks[i].Phase) > phaseIndex {
			return Task{}, errors.New("mission: task cannot depend on a later phase")
		}
	}
	t := Task{ID: domain.ID(), MissionID: c.mission.ID, Title: title, Archetype: role, Phase: phase, Priority: priority, Dependencies: slices.Clone(deps), Status: Pending, CreatedAt: time.Now().UTC()}
	c.tasks = append(c.tasks, t)
	c.blockDependents()
	return cloneTask(c.tasks[len(c.tasks)-1]), nil
}

// ConfigurePhases is a planning-time decision. Advance never skips failed or
// unfinished work and never invents tasks for an unsupported phase.
func (c *Control) ConfigurePhases(phases ...domain.KillChainPhase) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mission.Status != Planning || len(c.tasks) > 0 || len(phases) == 0 {
		return errors.New("mission: configure phases before adding tasks or starting")
	}
	seen := map[domain.KillChainPhase]bool{}
	for _, p := range phases {
		switch p {
		case domain.PhaseRecon, domain.PhaseWeaponize, domain.PhaseDeliver, domain.PhaseExploit, domain.PhaseInstall, domain.PhaseC2, domain.PhaseActions:
		default:
			return errors.New("mission: unknown phase")
		}
		if seen[p] {
			return errors.New("mission: duplicate phase")
		}
		seen[p] = true
	}
	c.mission.Phases = slices.Clone(phases)
	c.mission.Phase = phases[0]
	return nil
}
func (c *Control) AdvancePhase() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mission.Status != Active {
		return errors.New("mission: phase advancement requires an active mission")
	}
	i := slices.Index(c.mission.Phases, c.mission.Phase)
	if i < 0 || i+1 >= len(c.mission.Phases) {
		return errors.New("mission: no next phase")
	}
	found := false
	for _, t := range c.tasks {
		if t.Phase == c.mission.Phase {
			found = true
			if t.Status != TaskCompleted {
				return errors.New("mission: current phase has unfinished work")
			}
		}
	}
	if !found {
		return errors.New("mission: cannot advance an empty phase")
	}
	c.mission.Phase = c.mission.Phases[i+1]
	return nil
}

func validRole(r domain.Archetype) bool {
	switch r {
	case domain.ArchRecon, domain.ArchScanner, domain.ArchExploiter, domain.ArchInfiltrator, domain.ArchExfiltrator, domain.ArchGhost, domain.ArchCoordinator, domain.ArchAnalyst:
		return true
	}
	return false
}
func (c *Control) index(id string) int {
	for i := range c.tasks {
		if c.tasks[i].ID == id {
			return i
		}
	}
	return -1
}

// Claim atomically selects the highest priority ready task for an idle operator.
func (c *Control) Claim(role domain.Archetype, operatorID string) (Task, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mission.Status != Active || operatorID == "" {
		return Task{}, false
	}
	for _, t := range c.tasks {
		if t.Status == Running && t.OperatorID == operatorID {
			return Task{}, false
		}
	}
	best := -1
	for i, t := range c.tasks {
		if t.Status != Pending || t.Archetype != role || t.Phase != c.mission.Phase {
			continue
		}
		ready := true
		for _, dep := range t.Dependencies {
			if c.tasks[c.index(dep)].Status != TaskCompleted {
				ready = false
				break
			}
		}
		if ready && (best == -1 || t.Priority > c.tasks[best].Priority) {
			best = i
		}
	}
	if best < 0 {
		return Task{}, false
	}
	t := &c.tasks[best]
	t.Status = Running
	t.OperatorID = operatorID
	t.StartedAt = time.Now().UTC()
	return cloneTask(*t), true
}

func (c *Control) CompleteTask(id, result string) error { return c.finishTask(id, result, "") }
func (c *Control) FailTask(id, reason string) error {
	if reason == "" {
		return errors.New("mission: failure reason required")
	}
	return c.finishTask(id, "", reason)
}
func (c *Control) finishTask(id, result, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.index(id)
	if i < 0 {
		return errors.New("mission: task not found")
	}
	t := &c.tasks[i]
	if t.Status != Running || (c.mission.Status != Active && c.mission.Status != Paused) {
		return errors.New("mission: task is not running")
	}
	t.Status = TaskCompleted
	if reason != "" {
		t.Status = TaskFailed
	}
	t.Result = result
	t.Error = reason
	t.FinishedAt = time.Now().UTC()
	c.blockDependents()
	return nil
}
func (c *Control) blockDependents() {
	for i := range c.tasks {
		t := &c.tasks[i]
		if t.Status != Pending {
			continue
		}
		for _, dep := range t.Dependencies {
			s := c.tasks[c.index(dep)].Status
			if s == TaskFailed || s == Blocked || s == Cancelled {
				t.Status = Blocked
				t.Error = "dependency did not complete"
				t.FinishedAt = time.Now().UTC()
				break
			}
		}
	}
}

func (c *Control) Finish() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mission.Status != Active || len(c.tasks) == 0 {
		return errors.New("mission: no active completed work")
	}
	if c.mission.Phase != c.mission.Phases[len(c.mission.Phases)-1] {
		return errors.New("mission: remaining phases have not been reached")
	}
	for _, t := range c.tasks {
		if t.Status != TaskCompleted {
			return fmt.Errorf("mission: task %s is %s", t.ID, t.Status)
		}
	}
	for _, phase := range c.mission.Phases {
		found := false
		for _, task := range c.tasks {
			if task.Phase == phase {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("mission: phase %s has no completed work", phase)
		}
	}
	c.mission.Status = Completed
	c.mission.FinishedAt = time.Now().UTC()
	return nil
}
func (c *Control) Abort(reason string) error { return c.stop(Aborted, reason) }
func (c *Control) Fail(reason string) error  { return c.stop(Failed, reason) }
func (c *Control) stop(status Status, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mission.Status == Completed || c.mission.Status == Failed || c.mission.Status == Aborted {
		return errors.New("mission: already terminated")
	}
	if reason == "" {
		return errors.New("mission: termination reason required")
	}
	c.mission.Status = status
	c.mission.Reason = reason
	c.runtime.Abort(fmt.Errorf("%w: %s", ErrAborted, reason))
	c.mission.FinishedAt = time.Now().UTC()
	for i := range c.tasks {
		if c.tasks[i].Status == Pending || c.tasks[i].Status == Running {
			c.tasks[i].Status = Cancelled
			c.tasks[i].Error = reason
			c.tasks[i].FinishedAt = c.mission.FinishedAt
		}
	}
	return nil
}
