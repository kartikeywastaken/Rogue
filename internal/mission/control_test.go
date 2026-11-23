package mission

import (
	"sync"
	"sync/atomic"
	"testing"

	"rogue/internal/domain"
)

func newControl(t *testing.T) *Control {
	t.Helper()
	c, err := New("m", "assess local fixture", Rules{Scope: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func add(t *testing.T, c *Control, title string, role domain.Archetype, priority int, deps ...string) Task {
	t.Helper()
	task, err := c.AddTask(title, role, priority, deps...)
	if err != nil {
		t.Fatal(err)
	}
	return task
}
func TestDependencySchedulingAndSnapshots(t *testing.T) {
	c := newControl(t)
	a := add(t, c, "discover", domain.ArchRecon, 1)
	b := add(t, c, "assess", domain.ArchScanner, 100, a.ID)
	if _, err := c.AddTask("bad", domain.ArchRecon, 1, "another-mission-task"); err == nil {
		t.Fatal("accepted unknown dependency")
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Claim(domain.ArchScanner, "ARGUS"); ok {
		t.Fatal("dependency not enforced")
	}
	task, ok := c.Claim(domain.ArchRecon, "SIGINT")
	if !ok || task.ID != a.ID {
		t.Fatal("recon not ready")
	}
	if err := c.Finish(); err == nil {
		t.Fatal("completed running mission")
	}
	if err := c.CompleteTask(a.ID, "discovered fixture"); err != nil {
		t.Fatal(err)
	}
	if err := c.Pause(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Claim(domain.ArchScanner, "ARGUS"); ok {
		t.Fatal("dispatch during pause")
	}
	started := c.Snapshot().StartedAt
	if err := c.Resume(); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().StartedAt != started {
		t.Fatal("resume overwrote start time")
	}
	task, ok = c.Claim(domain.ArchScanner, "ARGUS")
	if !ok || task.ID != b.ID {
		t.Fatal("scanner not ready")
	}
	s := c.Snapshot()
	s.Tasks[1].Dependencies[0] = "mutated"
	s.Rules.Scope[0] = "mutated"
	if c.Snapshot().Tasks[1].Dependencies[0] != a.ID || c.Snapshot().Rules.Scope[0] != "localhost" {
		t.Fatal("snapshot aliases state")
	}
	if err := c.CompleteTask(b.ID, "checked"); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err == nil {
		t.Fatal("restarted completed mission")
	}
}
func TestFailureBlocksDescendants(t *testing.T) {
	c := newControl(t)
	a := add(t, c, "a", domain.ArchRecon, 1)
	b := add(t, c, "b", domain.ArchScanner, 1, a.ID)
	add(t, c, "c", domain.ArchAnalyst, 1, b.ID)
	_ = c.Start()
	_, _ = c.Claim(domain.ArchRecon, "SIGINT")
	if err := c.FailTask(a.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	if s.Tasks[1].Status != Blocked || s.Tasks[2].Status != Blocked {
		t.Fatal("descendants not blocked")
	}
	if err := c.Finish(); err == nil {
		t.Fatal("failed mission completed")
	}
	if err := c.Abort("stop"); err != nil {
		t.Fatal(err)
	}
	if err := c.CompleteTask(a.ID, "late"); err == nil {
		t.Fatal("late completion accepted")
	}
}
func TestClaimIsAtomicAndPriorityOrdered(t *testing.T) {
	c := newControl(t)
	add(t, c, "low", domain.ArchRecon, 1)
	high := add(t, c, "high", domain.ArchRecon, 10)
	_ = c.Start()
	var won atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if task, ok := c.Claim(domain.ArchRecon, "SIGINT"); ok {
				if task.ID != high.ID {
					t.Error("priority ignored")
				}
				won.Add(1)
			}
		})
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d simultaneous claims", won.Load())
	}
}
func TestRules(t *testing.T) {
	r := Rules{Scope: []string{"Example.COM", "192.0.2.0/24", "::1"}, Excluded: []string{"192.0.2.8"}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host string
		want bool
	}{{"example.com.", true}, {"sub.example.com", false}, {"example.com.evil", false}, {"192.0.2.7", true}, {"192.0.2.8", false}, {"::1", true}, {"198.51.100.1", false}} {
		if got := r.AllowsHost(tc.host); got != tc.want {
			t.Errorf("%s: %v", tc.host, got)
		}
	}
	if r.AllowsAddress("example.com", "192.0.2.8") {
		t.Fatal("IP exclusion bypassed by DNS name")
	}
	if (Rules{}).AllowsHost("localhost") {
		t.Fatal("empty scope is not deny-by-default")
	}
	if err := (Rules{Scope: []string{"https://example.com"}}).Validate(); err == nil {
		t.Fatal("URL accepted as scope")
	}
}

func TestPhaseAdvancementRequiresCompletedWork(t *testing.T) {
	c := newControl(t)
	if err := c.ConfigurePhases(domain.PhaseRecon, domain.PhaseActions); err != nil {
		t.Fatal(err)
	}
	a := add(t, c, "discover", domain.ArchRecon, 10)
	b, err := c.AddTaskInPhase(domain.PhaseActions, "report", domain.ArchAnalyst, 10, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Start()
	if err := c.AdvancePhase(); err == nil {
		t.Fatal("skipped recon")
	}
	if _, ok := c.Claim(domain.ArchAnalyst, "ORACLE"); ok {
		t.Fatal("dispatched future phase")
	}
	_, _ = c.Claim(domain.ArchRecon, "SIGINT")
	if err := c.CompleteTask(a.ID, "observed"); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err == nil {
		t.Fatal("skipped remaining phase")
	}
	if err := c.AdvancePhase(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Claim(domain.ArchAnalyst, "ORACLE"); !ok {
		t.Fatal("report not ready")
	}
	if err := c.CompleteTask(b.ID, "reported"); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyFinalPhaseCannotCompleteMission(t *testing.T) {
	c := newControl(t)
	if err := c.ConfigurePhases(domain.PhaseRecon, domain.PhaseActions); err != nil {
		t.Fatal(err)
	}
	a := add(t, c, "discover", domain.ArchRecon, 1)
	_ = c.Start()
	_, _ = c.Claim(domain.ArchRecon, "SIGINT")
	_ = c.CompleteTask(a.ID, "done")
	if err := c.AdvancePhase(); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err == nil {
		t.Fatal("empty final phase counted as completed")
	}
}
