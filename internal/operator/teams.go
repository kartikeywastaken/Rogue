package operator

import (
	"strings"

	"rogue/internal/domain"
)

// TeamComposition describes a named multi-operator team factory configuration.
type TeamComposition struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Roles       []domain.Archetype       `json:"roles"`
	Counts      map[domain.Archetype]int `json:"counts"` // desired parallel worker instances per role
	OPSECHint   string                   `json:"opsec_hint"`
}

// BalancedTeam returns the standard mix: recon -> scanner -> exploiter -> analyst.
func BalancedTeam() []Profile {
	p := Profiles()
	return []Profile{
		p[domain.ArchRecon],
		p[domain.ArchScanner],
		p[domain.ArchExploiter],
		p[domain.ArchAnalyst],
	}
}

// StealthTeam returns a low-noise composition: ghost leads, coordinator
// directs, and a single recon operator — minimal active footprint.
func StealthTeam() []Profile {
	p := Profiles()
	return []Profile{
		p[domain.ArchGhost],
		p[domain.ArchCoordinator],
		p[domain.ArchRecon],
		p[domain.ArchAnalyst],
	}
}

// BreachTeam returns an offensive composition with parallel exploiters,
// infiltrator, and exfiltrator for deep authorized lab assessments.
func BreachTeam() []Profile {
	p := Profiles()
	return []Profile{
		p[domain.ArchExploiter],
		p[domain.ArchExploiter],
		p[domain.ArchInfiltrator],
		p[domain.ArchExfiltrator],
		p[domain.ArchAnalyst],
	}
}

// AvailableTeams returns all built-in team factory compositions.
func AvailableTeams() []TeamComposition {
	return []TeamComposition{
		{
			Name:        "balanced",
			Description: "Standard full-coverage assessment team (SIGINT, ARGUS, BREACH, ORACLE)",
			Roles:       []domain.Archetype{domain.ArchRecon, domain.ArchScanner, domain.ArchExploiter, domain.ArchAnalyst},
			Counts:      map[domain.Archetype]int{domain.ArchRecon: 1, domain.ArchScanner: 1, domain.ArchExploiter: 1, domain.ArchAnalyst: 1},
			OPSECHint:   "covert",
		},
		{
			Name:        "stealth",
			Description: "Low-footprint passive/evasion team (PHANTOM, OVERWATCH, SIGINT, ORACLE)",
			Roles:       []domain.Archetype{domain.ArchGhost, domain.ArchCoordinator, domain.ArchRecon, domain.ArchAnalyst},
			Counts:      map[domain.Archetype]int{domain.ArchGhost: 1, domain.ArchCoordinator: 1, domain.ArchRecon: 1, domain.ArchAnalyst: 1},
			OPSECHint:   "silent",
		},
		{
			Name:        "breach",
			Description: "Parallel exploitation & post-access team with 2 BREACH exploiters (BREACH x2, SHADOW, COURIER, ORACLE)",
			Roles:       []domain.Archetype{domain.ArchExploiter, domain.ArchInfiltrator, domain.ArchExfiltrator, domain.ArchAnalyst},
			Counts:      map[domain.Archetype]int{domain.ArchExploiter: 2, domain.ArchInfiltrator: 1, domain.ArchExfiltrator: 1, domain.ArchAnalyst: 1},
			OPSECHint:   "loud",
		},
	}
}

// LookupTeam resolves a named team factory ("balanced", "stealth", "breach").
func LookupTeam(name string) (TeamComposition, bool) {
	target := strings.ToLower(strings.TrimSpace(name))
	for _, t := range AvailableTeams() {
		if t.Name == target {
			return t, true
		}
	}
	return TeamComposition{}, false
}
