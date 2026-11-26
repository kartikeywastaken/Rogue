package operator

import (
	"slices"
	"testing"

	"rogue/internal/domain"
)

func TestExploitCategoryReachable(t *testing.T) {
	profiles := Profiles()

	// At least one profile must include "exploit"
	found := false
	for arch, p := range profiles {
		if slices.Contains(p.ToolCats, "exploit") {
			t.Logf("%s includes exploit category", arch)
			found = true
		}
	}
	if !found {
		t.Fatal("no operator profile permits the 'exploit' tool category — exploit/sandbox tools are unreachable through missions")
	}

	// Exploiter specifically must have exploit
	exp := profiles[domain.ArchExploiter]
	if !slices.Contains(exp.ToolCats, "exploit") {
		t.Fatalf("ArchExploiter missing 'exploit' category: %v", exp.ToolCats)
	}
}

func TestCTFCategoryReachable(t *testing.T) {
	profiles := Profiles()

	found := false
	for arch, p := range profiles {
		if slices.Contains(p.ToolCats, "ctf") {
			t.Logf("%s includes ctf category", arch)
			found = true
		}
	}
	if !found {
		t.Fatal("no operator profile permits the 'ctf' tool category — CTF tools are unreachable through missions")
	}

	// Exploiter must have ctf for CTF benchmark challenges
	exp := profiles[domain.ArchExploiter]
	if !slices.Contains(exp.ToolCats, "ctf") {
		t.Fatalf("ArchExploiter missing 'ctf' category: %v", exp.ToolCats)
	}
}

func TestAllProfilesHaveRequiredFields(t *testing.T) {
	for arch, p := range Profiles() {
		if p.Archetype == "" {
			t.Errorf("%s: empty Archetype", arch)
		}
		if p.Callsign == "" {
			t.Errorf("%s: empty Callsign", arch)
		}
		if p.Phase == "" {
			t.Errorf("%s: empty Phase", arch)
		}
		if p.SystemPrompt == "" {
			t.Errorf("%s: empty SystemPrompt", arch)
		}
		if len(p.ToolCats) == 0 {
			t.Errorf("%s: empty ToolCats", arch)
		}
	}
}

func TestExploitToolsPolicyIntegration(t *testing.T) {
	// Verify that exploit category is accessible through the operator
	// profiles that need it, and not accidentally granted to operators
	// that shouldn't have it.
	profiles := Profiles()

	// These should have exploit
	exploitOperators := []domain.Archetype{
		domain.ArchExploiter,
		domain.ArchInfiltrator,
		domain.ArchScanner,
	}
	for _, arch := range exploitOperators {
		p := profiles[arch]
		if !slices.Contains(p.ToolCats, "exploit") {
			t.Errorf("%s should have 'exploit' category but has: %v", arch, p.ToolCats)
		}
	}

	// These should NOT have exploit
	noExploitOperators := []domain.Archetype{
		domain.ArchRecon,
		domain.ArchGhost,
		domain.ArchAnalyst,
	}
	for _, arch := range noExploitOperators {
		p := profiles[arch]
		if slices.Contains(p.ToolCats, "exploit") {
			t.Errorf("%s should NOT have 'exploit' category but has: %v", arch, p.ToolCats)
		}
	}
}
