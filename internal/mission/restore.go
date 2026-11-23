package mission

import (
	"errors"
	"fmt"
	"slices"
)

// Restore validates saved state. Interrupted tasks are cancelled, not replayed:
// a process crash can leave an external operation's outcome unknown.
func Restore(saved Mission, interrupted bool) (*Control, error) {
	if saved.ID == "" {
		return nil, errors.New("mission: missing saved ID")
	}
	control, err := New(saved.ID, saved.Objective, saved.Rules)
	if err != nil {
		return nil, err
	}
	if err := control.ConfigurePhases(saved.Phases...); err != nil {
		return nil, err
	}
	if !slices.Contains(saved.Phases, saved.Phase) {
		return nil, errors.New("mission: invalid saved current phase")
	}
	switch saved.Status {
	case Planning, Active, Paused, Completed, Failed, Aborted:
	default:
		return nil, errors.New("mission: invalid saved status")
	}
	seen := map[string]bool{}
	for _, task := range saved.Tasks {
		if task.ID == "" || seen[task.ID] || task.MissionID != saved.ID || !validRole(task.Archetype) || !slices.Contains(saved.Phases, task.Phase) {
			return nil, errors.New("mission: invalid saved task")
		}
		for _, dependency := range task.Dependencies {
			if !seen[dependency] {
				return nil, errors.New("mission: invalid or cyclic saved dependency")
			}
		}
		switch task.Status {
		case Pending, Running, TaskCompleted, TaskFailed, Blocked, Cancelled:
		default:
			return nil, errors.New("mission: invalid saved task status")
		}
		seen[task.ID] = true
		control.tasks = append(control.tasks, cloneTask(task))
	}
	control.mission = saved
	control.mission.Tasks = nil
	control.mission.Progress = 0
	control.mission.CompletedTasks = 0
	control.mission.FailedTasks = 0
	control.mission.BlockedTasks = 0
	control.mission.Rules = saved.Rules.clone()
	control.mission.Phases = slices.Clone(saved.Phases)
	if saved.Status == Paused {
		control.runtime.Pause()
	}
	if interrupted && (saved.Status == Active || saved.Status == Paused || saved.Status == Planning) {
		if err := control.Abort("recovered after process interruption; unfinished operation outcomes are unknown and will not be replayed"); err != nil {
			return nil, err
		}
	}
	if saved.Status == Completed {
		// Apply the same completion guards used during execution, rather than
		// trusting the word "completed" in an otherwise inconsistent snapshot.
		control.mission.Status = Active
		if err := control.Finish(); err != nil {
			return nil, fmt.Errorf("mission: inconsistent completed snapshot: %w", err)
		}
		control.mission.FinishedAt = saved.FinishedAt
	}
	return control, nil
}
