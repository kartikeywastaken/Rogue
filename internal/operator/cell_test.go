package operator

import (
	"testing"
	"time"

	"rogue/internal/domain"
)

func TestTeamsAndDynamicCellScaling(t *testing.T) {
	if _, ok := LookupTeam("breach"); !ok {
		t.Fatal("expected breach team factory")
	}
	if len(BalancedTeam()) != 4 || len(StealthTeam()) != 4 || len(BreachTeam()) != 5 {
		t.Fatal("unexpected team factory profile counts")
	}

	cell := NewCell(4, 0)
	comp, _ := LookupTeam("breach")
	cell.ConfigureTeam(comp)

	exploiters := 0
	for _, a := range cell.Snapshot() {
		if a.Profile.Archetype == domain.ArchExploiter {
			exploiters++
		}
	}
	if exploiters != 2 {
		t.Fatalf("expected 2 exploiters after BreachTeam config, got %d", exploiters)
	}

	// Verify scaling under queue pressure respects maxPerArchetype (3).
	spawned := cell.ScaleForQueue(map[domain.Archetype]int{
		domain.ArchScanner: 5,
	})
	if spawned != 2 { // 1 primary + 2 extras = 3 cap
		t.Fatalf("expected 2 additional scanners spawned up to cap 3, got %d", spawned)
	}

	// Verify BeginWorker / ExecuteWorker / FinishWorker lifecycle on spawned worker ID.
	if err := cell.BeginWorker("ARGUS-2", domain.ArchScanner, "task-1"); err != nil {
		t.Fatal(err)
	}
	_, cancelFn, err := cell.ExecuteWorker(t.Context(), "ARGUS-2")
	if err != nil {
		t.Fatal(err)
	}
	cancelFn()
	cell.FinishWorker("ARGUS-2", nil)

	// Verify Burn + EnsureAvailable spawns replacement when capped allows.
	if err := cell.Burn(domain.ArchRecon, "test burn"); err != nil {
		t.Fatal(err)
	}
	if !cell.EnsureAvailable(domain.ArchRecon) {
		t.Fatal("expected EnsureAvailable to spawn replacement recon operator")
	}
	_ = time.Millisecond
}
