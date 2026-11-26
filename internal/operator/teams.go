package operator

import "rogue/internal/domain"

// BalancedTeam returns the standard mix: recon → scanner → exploiter → analyst.
// Good for general-purpose engagements.
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
// directs, and a single recon operator — no active scanners.
func StealthTeam() []Profile {
	p := Profiles()
	return []Profile{
		p[domain.ArchGhost],
		p[domain.ArchCoordinator],
		p[domain.ArchRecon],
	}
}

// BreachTeam returns an offensive composition: exploiter, infiltrator, and
// exfiltrator — assumes recon is already complete.
func BreachTeam() []Profile {
	p := Profiles()
	return []Profile{
		p[domain.ArchExploiter],
		p[domain.ArchInfiltrator],
		p[domain.ArchExfiltrator],
	}
}
