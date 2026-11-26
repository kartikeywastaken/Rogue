package operator

import (
	"context"
	"errors"
	"fmt"
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

const maxPerArchetype = 3

type Cell struct {
	mu               sync.Mutex
	agents           map[domain.Archetype]Agent
	workers          map[string]*Agent // keyed by worker ID for dynamic multi-worker scaling
	capacity, active int
	cooldown         time.Duration
	cancels          map[string]context.CancelCauseFunc
	spawnCounts      map[domain.Archetype]int
}

func NewCell(capacity int, cooldown time.Duration) *Cell {
	if capacity < 1 {
		capacity = 2
	}
	if capacity > 8 {
		capacity = 8
	}
	cell := &Cell{
		agents:      make(map[domain.Archetype]Agent),
		workers:     make(map[string]*Agent),
		capacity:    capacity,
		cooldown:    cooldown,
		cancels:     make(map[string]context.CancelCauseFunc),
		spawnCounts: make(map[domain.Archetype]int),
	}
	for role, profile := range Profiles() {
		a := Agent{ID: profile.Callsign, Profile: profile, State: domain.StateIdle}
		cell.agents[role] = a
		cell.workers[a.ID] = &a
		cell.spawnCounts[role] = 1
	}
	return cell
}

// Spawn creates an additional worker instance for role (e.g. ARGUS-2) up to
// maxPerArchetype per archetype. Returns the newly created Agent.
func (cell *Cell) Spawn(role domain.Archetype) (Agent, error) {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	profile, ok := Profiles()[role]
	if !ok {
		return Agent{}, fmt.Errorf("unknown operator archetype %q", role)
	}
	count := cell.spawnCounts[role]
	if count >= maxPerArchetype {
		return Agent{}, fmt.Errorf("archetype %s reached max worker cap (%d)", role, maxPerArchetype)
	}
	count++
	cell.spawnCounts[role] = count
	id := fmt.Sprintf("%s-%d", profile.Callsign, count)
	a := Agent{ID: id, Profile: profile, State: domain.StateIdle}
	cell.workers[id] = &a
	return a, nil
}

// ConfigureTeam pre-spawns any additional archetype counts defined by a
// TeamComposition (for example, 2 parallel exploiters in BreachTeam).
func (cell *Cell) ConfigureTeam(comp TeamComposition) {
	for role, want := range comp.Counts {
		if want <= 1 {
			continue
		}
		if want > maxPerArchetype {
			want = maxPerArchetype
		}
		for i := 1; i < want; i++ {
			_, _ = cell.Spawn(role)
		}
	}
}

// ScaleForQueue spawns additional workers for archetypes whose pending task
// queue depth exceeds available idle workers (capped at maxPerArchetype and cell capacity).
// Returns the number of newly spawned workers.
func (cell *Cell) ScaleForQueue(pendingByRole map[domain.Archetype]int) int {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	now := time.Now()
	idleByRole := make(map[domain.Archetype]int)
	for _, w := range cell.workers {
		st := w.State
		if st == domain.StateCooldown && !now.Before(w.ReadyAt) {
			st = domain.StateIdle
		}
		if st == domain.StateIdle && w.TaskID == "" {
			idleByRole[w.Profile.Archetype]++
		}
	}
	spawned := 0
	for role, pending := range pendingByRole {
		if pending <= idleByRole[role] {
			continue
		}
		profile, ok := Profiles()[role]
		if !ok {
			continue
		}
		for pending > idleByRole[role] && cell.spawnCounts[role] < maxPerArchetype && len(cell.workers) < cell.capacity*4 {
			cell.spawnCounts[role]++
			id := fmt.Sprintf("%s-%d", profile.Callsign, cell.spawnCounts[role])
			a := Agent{ID: id, Profile: profile, State: domain.StateIdle}
			cell.workers[id] = &a
			idleByRole[role]++
			spawned++
		}
	}
	return spawned
}

// Begin claims the primary worker slot for role. Preserved for backward compatibility.
func (cell *Cell) Begin(role domain.Archetype, taskID string) error {
	profile, ok := Profiles()[role]
	if !ok {
		return errors.New("operator unavailable or cell at capacity")
	}
	return cell.BeginWorker(profile.Callsign, role, taskID)
}

// BeginWorker assigns taskID to a specific worker ID (primary or auto-spawned).
func (cell *Cell) BeginWorker(workerID string, role domain.Archetype, taskID string) error {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	w, found := cell.workers[workerID]
	if !found || cell.active >= cell.capacity || w.TaskID != "" || w.State == domain.StateBurned || time.Now().Before(w.ReadyAt) {
		return errors.New("operator unavailable or cell at capacity")
	}
	w.TaskID = taskID
	w.State = domain.StateTasked
	cell.syncPrimary(w)
	cell.active++
	return nil
}

// Execute starts the primary worker for role. Preserved for backward compatibility.
func (cell *Cell) Execute(parent context.Context, role domain.Archetype) (context.Context, func(), error) {
	profile, ok := Profiles()[role]
	if !ok {
		return nil, nil, errors.New("operator has no assigned task")
	}
	return cell.ExecuteWorker(parent, profile.Callsign)
}

// ExecuteWorker starts execution for workerID.
func (cell *Cell) ExecuteWorker(parent context.Context, workerID string) (context.Context, func(), error) {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	w, found := cell.workers[workerID]
	if !found || w.State != domain.StateTasked {
		return nil, nil, errors.New("operator has no assigned task")
	}
	ctx, cancel := context.WithCancelCause(parent)
	cell.cancels[workerID] = cancel
	w.State = domain.StateExecuting
	cell.syncPrimary(w)
	return ctx, func() { cancel(context.Canceled) }, nil
}

// Burn permanently retires the primary worker for role.
func (cell *Cell) Burn(role domain.Archetype, reason string) error {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	profile, found := Profiles()[role]
	if !found || reason == "" {
		return errors.New("operator and burn reason required")
	}
	w, ok := cell.workers[profile.Callsign]
	if !ok {
		return errors.New("operator and burn reason required")
	}
	w.State = domain.StateBurned
	w.BurnReason = reason
	cell.syncPrimary(w)
	if cancel := cell.cancels[profile.Callsign]; cancel != nil {
		cancel(errors.New("operator burned: " + reason))
	}
	return nil
}

// Finish completes execution on the primary worker for role.
func (cell *Cell) Finish(role domain.Archetype, failure error) {
	if profile, ok := Profiles()[role]; ok {
		cell.FinishWorker(profile.Callsign, failure)
	}
}

// FinishWorker marks workerID finished, updates stats/risk, and applies cooldown.
func (cell *Cell) FinishWorker(workerID string, failure error) {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	w, ok := cell.workers[workerID]
	if !ok || w.TaskID == "" {
		return
	}
	w.TaskID = ""
	if w.State != domain.StateBurned {
		w.State = domain.StateCooldown
	}
	delete(cell.cancels, workerID)
	w.ReadyAt = time.Now().Add(cell.cooldown)
	if failure == nil {
		w.Completed++
	} else {
		w.Failed++
		w.LastError = failure.Error()
		// Failure-risk heuristic from the paper, not measured detection.
		w.Risk = min(1, float64(w.Failed)/10)
		if w.Risk >= 0.7 {
			w.State = domain.StateBurned
			w.BurnReason = "failure-risk threshold reached"
		}
	}
	cell.syncPrimary(w)
	cell.active--
}

// EnsureAvailable spawns a fresh worker for role if existing workers are burned
// and per-archetype capacity remains.
func (cell *Cell) EnsureAvailable(role domain.Archetype) bool {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	now := time.Now()
	for _, w := range cell.workers {
		if w.Profile.Archetype == role && w.State != domain.StateBurned && w.TaskID == "" && !now.Before(w.ReadyAt) {
			return true
		}
	}
	if cell.spawnCounts[role] >= maxPerArchetype {
		return false
	}
	profile, ok := Profiles()[role]
	if !ok {
		return false
	}
	cell.spawnCounts[role]++
	id := fmt.Sprintf("%s-%d", profile.Callsign, cell.spawnCounts[role])
	a := Agent{ID: id, Profile: profile, State: domain.StateIdle}
	cell.workers[id] = &a
	return true
}

func (cell *Cell) syncPrimary(w *Agent) {
	if w.ID == w.Profile.Callsign {
		cell.agents[w.Profile.Archetype] = *w
	}
}

func (cell *Cell) Snapshot() []Agent {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	now := time.Now()
	result := make([]Agent, 0, len(cell.workers))
	for _, w := range cell.workers {
		cp := *w
		if cp.State == domain.StateCooldown && !now.Before(cp.ReadyAt) {
			cp.State = domain.StateIdle
		}
		cp.Profile.ToolCats = append([]string{}, cp.Profile.ToolCats...)
		result = append(result, cp)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
