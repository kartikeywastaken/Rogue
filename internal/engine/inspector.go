package engine

import (
	"time"

	"rogue/internal/comms"
	"rogue/internal/domain"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/operator"
	"rogue/internal/opsec"
	"rogue/internal/target"
)

// WarRoomSnapshot is the read-only, lock-safe projection of a live or saved
// mission designed for consumption by the HTTP API and the Phase 4 TUI War Room
// without breaking the core engine.Engine interface.
type WarRoomSnapshot struct {
	MissionID         string                  `json:"mission_id"`
	Team              string                  `json:"team,omitempty"`
	TokenLimit        int                     `json:"token_limit,omitempty"`
	CostLimit         float64                 `json:"cost_limit,omitempty"`
	Objective         string                  `json:"objective"`
	Status            mission.Status          `json:"status"`
	Phase             domain.KillChainPhase   `json:"phase"`
	Phases            []domain.KillChainPhase `json:"phases"`
	Progress          float64                 `json:"progress"`
	CreatedAt         time.Time               `json:"created_at"`
	StartedAt         time.Time               `json:"started_at"`
	Tasks             []mission.Task          `json:"tasks"`
	Operators         []operator.Agent        `json:"operators"`
	Targets           target.Snapshot         `json:"targets"`
	Findings          []domain.Finding        `json:"findings"`
	ObservationsCount int                     `json:"observations_count"`
	SuccessfulObs     int                     `json:"successful_obs"`
	FailedObs         int                     `json:"failed_obs"`
	PendingApprovals  int                     `json:"pending_approvals"`
	OPSEC             opsec.Snapshot          `json:"opsec"`
	OPSECProfile      string                  `json:"opsec_profile"`
	RoEPreset         string                  `json:"roe_preset"`
	Detections        int                     `json:"detections"`
	Spending          llm.Spending            `json:"spending"`
	Messages          []comms.Message         `json:"messages"`
}

// Inspector is the optional Phase 1 seam implemented by *Harness so TUI/API
// war-room views can observe mission topology, operators, OPSEC, and vault
// progress safely.
type Inspector interface {
	Inspect(id string) (WarRoomSnapshot, error)
	LiveSnapshot() (WarRoomSnapshot, bool)
}

// Inspect builds a WarRoomSnapshot for a live or persisted mission ID.
func (harness *Harness) Inspect(id string) (WarRoomSnapshot, error) {
	if state, err := harness.activeRun(id); err == nil {
		state.mu.Lock()
		defer state.mu.Unlock()
		return snapshotFromRunState(state), nil
	}
	report, err := harness.Report(id)
	if err != nil {
		return WarRoomSnapshot{}, err
	}
	return WarRoomSnapshot{
		MissionID:         report.Mission.ID,
		Objective:         report.Mission.Objective,
		Status:            report.Mission.Status,
		Phase:             report.Mission.Phase,
		Phases:            report.Mission.Phases,
		Progress:          report.Mission.Progress,
		CreatedAt:         report.Mission.CreatedAt,
		StartedAt:         report.Mission.StartedAt,
		Tasks:             report.Mission.Tasks,
		Operators:         report.Operators,
		Targets:           report.Targets,
		Findings:          report.Evidence.Findings,
		ObservationsCount: report.Analysis.SuccessfulObservations + report.Analysis.FailedObservations,
		SuccessfulObs:     report.Analysis.SuccessfulObservations,
		FailedObs:         report.Analysis.FailedObservations,
		OPSEC:             report.OPSEC,
		OPSECProfile:      opsec.ActiveProfileSnapshot().Name,
		RoEPreset:         opsec.ActiveRoESnapshot().Name,
		Spending:          report.Spending,
		Messages:          report.Messages,
	}, nil
}

// LiveSnapshot returns a snapshot of the most recent active mission, if any.
func (harness *Harness) LiveSnapshot() (WarRoomSnapshot, bool) {
	state := harness.LastRun()
	if state == nil {
		return WarRoomSnapshot{}, false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return snapshotFromRunState(state), true
}

func snapshotFromRunState(state *RunState) WarRoomSnapshot {
	m := state.Control.Snapshot()
	pub := state.Evidence.PublicSnapshot()
	obs := state.Evidence.Observations()
	succ, fail := 0, 0
	for _, o := range obs {
		if o.Success {
			succ++
		} else {
			fail++
		}
	}
	return WarRoomSnapshot{
		Team: state.team, TokenLimit: state.tokenLimit, CostLimit: state.costLimit,
		MissionID:         m.ID,
		Objective:         m.Objective,
		Status:            m.Status,
		Phase:             m.Phase,
		Phases:            m.Phases,
		Progress:          m.Progress,
		CreatedAt:         m.CreatedAt,
		StartedAt:         m.StartedAt,
		Tasks:             m.Tasks,
		Operators:         state.Cell.Snapshot(),
		Targets:           state.Targets.Snapshot(),
		Findings:          pub.Findings,
		ObservationsCount: len(obs),
		SuccessfulObs:     succ,
		FailedObs:         fail,
		PendingApprovals:  state.approvalRequests,
		OPSEC:             state.OPSEC.Snapshot(),
		OPSECProfile:      state.opsecProfile,
		RoEPreset:         state.roePreset,
		Detections:        state.detections,
		Spending:          state.Budget.Snapshot(),
		Messages:          publicMessages(state.Comms.History("")),
	}
}
