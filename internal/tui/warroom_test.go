package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"rogue/internal/arsenal"
	"rogue/internal/bench"
	"rogue/internal/comms"
	"rogue/internal/domain"
	"rogue/internal/engine"
	"rogue/internal/mission"
	"rogue/internal/operator"
	"rogue/internal/target"
)

type inspectingEngine struct {
	scripted
	snapshot engine.WarRoomSnapshot
}

func (e inspectingEngine) Inspect(string) (engine.WarRoomSnapshot, error) { return e.snapshot, nil }
func (e inspectingEngine) LiveSnapshot() (engine.WarRoomSnapshot, bool)   { return e.snapshot, true }

func warFixture(w, h int) Model {
	now := time.Date(2026, 11, 27, 14, 32, 0, 0, time.UTC)
	snap := engine.WarRoomSnapshot{MissionID: "mission-7f32", Objective: "Assess the authorized local fixture", Status: mission.Active, Phase: domain.PhaseExploit, Phases: []domain.KillChainPhase{domain.PhaseRecon, domain.PhaseWeaponize}, OPSECProfile: "covert", RoEPreset: "default", TokenLimit: 50000, Detections: 1}
	for _, role := range []domain.Archetype{domain.ArchRecon, domain.ArchScanner, domain.ArchExploiter, domain.ArchInfiltrator, domain.ArchExfiltrator, domain.ArchGhost, domain.ArchCoordinator, domain.ArchAnalyst} {
		p := operator.Profiles()[role]
		snap.Operators = append(snap.Operators, operator.Agent{ID: p.Callsign, Profile: p, State: domain.StateExecuting, Completed: 3, Risk: .2})
	}
	snap.Targets = target.Snapshot{Hosts: []target.Host{{ID: "host-1", Name: "127.0.0.1", Services: []target.Service{{Port: 3000, Protocol: "tcp", Name: "http", Product: "Express", CPE: []string{"cpe:/a:fixture"}}}}}}
	snap.Findings = []domain.Finding{{ID: "finding-1", Title: "SQL error observed", Description: strings.Repeat("Evidence details · 测试 🔎 ", 30), Severity: domain.SevHigh, CVSS: 8.1, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", TargetID: "127.0.0.1", Evidence: []string{"obs-12"}, CWE: "CWE-89", CVE: []string{"CVE-2026-0001"}, Remediation: "Use parameterized queries"}, {ID: "info-1", Title: "Server header", Severity: domain.SevInfo, TargetID: "127.0.0.1"}}
	snap.Messages = []comms.Message{{From: "SIGINT", Content: "Observed HTTP service on 127.0.0.1:3000", CreatedAt: now}, {From: "BREACH", Content: "Reviewing recorded injection evidence", CreatedAt: now}}
	m := sized(inspectingEngine{snapshot: snap}, w, h)
	m.phase = phaseWarRoom
	m.war.snapshot = snap
	m.war.haveSnapshot = true
	m.war.collapsed = map[string]bool{}
	m.war.benchmarks = map[string]bench.SuiteResult{}
	m.war.profile, m.war.roe, m.war.team = "covert", "default", "balanced"
	m.war.catalog = []arsenal.Capability{{Name: "nmap_scan", Category: "recon", Availability: "available", Description: "Scan authorized hosts"}, {Name: "nuclei_scan", Category: "vuln", Availability: "nuclei not installed"}, {Name: "exploit_verify", Category: "lab", LabOnly: true, Availability: "available"}}
	m.push(entry{kind: entUser, text: "Assess http://127.0.0.1:3000"})
	m.push(entry{kind: entTool, tool: engine.ToolCall{ID: "task-1/tool-1", Name: "nmap_scan", Input: `{"host":"127.0.0.1"}`, Output: "1 open service", OK: true}})
	m.input.Blur()
	m.layout()
	return m
}

func assertUnclippedFrame(t *testing.T, m Model) {
	t.Helper()
	raw := m.viewWarRoom()
	if lipgloss.Height(raw) > m.height || lipgloss.Width(raw) > m.width {
		t.Fatalf("layout exceeds %dx%d: %dx%d", m.width, m.height, lipgloss.Width(raw), lipgloss.Height(raw))
	}
	checkFrame(t, m, m.width, m.height)
	if m.View().BackgroundColor != colGround {
		t.Fatal("War Room changed the theme ground")
	}
}

func TestWarRoomAllPanelsAndOverlaysFit(t *testing.T) {
	for _, sz := range [][2]int{{28, 10}, {60, 16}, {79, 24}, {80, 24}, {119, 34}, {120, 34}, {200, 50}} {
		for tab := range warTabs {
			t.Run(fmt.Sprintf("%dx%d/tab%d", sz[0], sz[1], tab), func(t *testing.T) {
				m := warFixture(sz[0], sz[1])
				m.war.tab = tab
				assertUnclippedFrame(t, m)
				if sz[0] >= 80 {
					for _, want := range []string{"mission-7f32", "det", "esc session"} {
						if !strings.Contains(frame(m), want) {
							t.Errorf("missing persistent telemetry/help %q", want)
						}
					}
				}
				for _, kind := range []string{"export", "quick", "pager"} {
					m.war.modal = ""
					switch kind {
					case "export":
						m.war.modal = kind
					case "quick":
						m.openWarForm(kind, "Quick run", strings.Repeat("测🔎", 120))
					case "pager":
						m.openWarPager(strings.Repeat("full JSON output 测试\n", 100))
					}
					assertUnclippedFrame(t, m)
				}
				m.war.approvals = []approvalMsg{{request: engine.ApprovalRequest{MissionID: "mission-7f32", Tool: "nmap_scan", Target: "127.0.0.1", Arguments: json.RawMessage(`{"host":"127.0.0.1"}`)}}}
				checkFrame(t, m, sz[0], sz[1])
			})
		}
	}
}

func TestWarRoomTogglePreservesRunningTurnAndDraft(t *testing.T) {
	m := sized(scripted{}, 120, 34)
	m = typeText(m, "assess fixture")
	m, _ = press(m, tea.KeyEnter)
	events := m.events
	m.input.SetValue("draft")
	m, cmd := press(m, 'w', tea.ModCtrl)
	if m.phase != phaseWarRoom || !m.running || m.events != events || cmd == nil {
		t.Fatal("toggle lost active turn")
	}
	m, _ = press(m, tea.KeyEscape)
	if m.phase != phaseSession || !m.running || m.input.Value() != "draft" {
		t.Fatal("esc must preserve turn and draft")
	}
	m.stopTurn()
}

func TestWarRoomInputFilterSeverityAndTree(t *testing.T) {
	m := warFixture(120, 34)
	m, _ = press(m, 'i')
	m = typeText(m, "123 q y n space")
	if m.input.Value() != "123 q y n space" || m.war.tab != 0 {
		t.Fatal("navigation consumed text input")
	}
	m, _ = press(m, tea.KeyEscape)
	m, _ = press(m, '4')
	m, _ = press(m, 'h')
	if len(m.filteredFindings()) != 1 {
		t.Fatal("high filter")
	}
	m, _ = press(m, 'i')
	if m.war.composing || m.filteredFindings()[0].Severity != domain.SevInfo {
		t.Fatal("info filter conflicted with input")
	}
	m, _ = press(m, 'a')
	m, _ = press(m, tea.KeyEnter)
	if m.war.modal != "pager" || !strings.Contains(m.war.pager.View(), "finding-1") {
		t.Fatal("finding details missing")
	}
	m, _ = press(m, tea.KeyEscape)
	m, _ = press(m, '5')
	m, _ = press(m, '/')
	m = typeText(m, "nuclei")
	if len(m.filteredCatalog()) != 1 || m.war.tab != 4 {
		t.Fatal("tool filter")
	}
	m, _ = press(m, tea.KeyEnter)
	m, _ = press(m, tea.KeyEnter)
	if !strings.Contains(m.war.err, "not installed") {
		t.Fatal("missing tool should report availability")
	}
	m, _ = press(m, '3')
	before := len(m.targetTree())
	m, _ = press(m, tea.KeyEnter)
	if len(m.targetTree()) >= before {
		t.Fatal("host did not collapse")
	}
	m, _ = press(m, tea.KeyEnter)
	if len(m.targetTree()) != before {
		t.Fatal("host did not expand")
	}
}

func TestWarRoomActionsAreCommandsAndValidateJSON(t *testing.T) {
	m := warFixture(120, 34)
	calls := 0
	m.setupCfg = &Setup{WarRoom: &WarRoomServices{QuickRun: func(_ context.Context, _ engine.Engine, name string, args json.RawMessage, role domain.Archetype, mode engine.Mode) (engine.Report, error) {
		calls++
		if name != "nmap_scan" || role != domain.ArchScanner || string(args) != `{"host":"127.0.0.1"}` {
			t.Errorf("wrong exact action %s %s %s", name, args, role)
		}
		return engine.Report{}, nil
	}}}
	m.war.tab = 4
	m, _ = press(m, tea.KeyEnter)
	if calls != 0 || m.war.modal != "quick" {
		t.Fatal("opening form must not execute")
	}
	m.war.form.SetValue(`{"operator":"scanner","arguments":null}`)
	m, _ = press(m, tea.KeyEnter)
	if calls != 0 || m.war.modal != "quick" || m.war.err == "" {
		t.Fatal("invalid JSON action accepted")
	}
	m.war.form.SetValue(`{"operator":"scanner","arguments":{"host":"127.0.0.1"}}`)
	m, cmd := press(m, tea.KeyEnter)
	if calls != 0 || cmd == nil || !m.war.busy {
		t.Fatal("execution must be asynchronous")
	}
	msg := cmd()
	next, _ := m.Update(msg)
	m = next.(Model)
	if calls != 1 || m.war.busy || m.war.modal != "pager" {
		t.Fatal("result did not reach Elm loop")
	}
}

func TestWarRoomApprovalsAndCancellation(t *testing.T) {
	for key, want := range map[rune]engine.ApprovalDecision{'y': engine.ApprovalOnce, 'a': engine.ApprovalMission, 'n': engine.ApprovalDeny} {
		m := warFixture(100, 30)
		reply := make(chan engine.ApprovalDecision, 1)
		m.war.approvals = []approvalMsg{{reply: reply, request: engine.ApprovalRequest{Tool: "exact_tool", Arguments: json.RawMessage(`{"url":"http://127.0.0.1"}`)}}}
		if !strings.Contains(frame(m), "[y] allow once") {
			t.Fatal("decision keys missing")
		}
		m, _ = press(m, key)
		if got := <-reply; got != want {
			t.Fatalf("decision %v", got)
		}
		if len(m.war.approvals) != 0 {
			t.Fatal("approval not dismissed")
		}
	}
	done := make(chan struct{})
	m := warFixture(100, 30)
	m.war.approvals = []approvalMsg{{done: done}}
	close(done)
	next, _ := m.Update(warTickMsg{})
	if len(next.(Model).war.approvals) != 0 {
		t.Fatal("expired approval stayed open")
	}
}

func TestRunTurnObserverOrderAndAbort(t *testing.T) {
	for _, terminal := range []engine.Kind{engine.KindDone, engine.KindError} {
		var got []string
		eng := scripted{events: []engine.Event{{Kind: engine.KindToolStart}, {Kind: engine.KindToolEnd}, {Kind: terminal}}}
		for range runTurn(context.Background(), eng, engine.Request{}, func(kind string, _ engine.Event) error { got = append(got, kind); return nil }) {
		}
		want := "start,event,event,complete"
		if terminal == engine.KindError {
			want = "start,event,event,abort"
		}
		if strings.Join(got, ",") != want {
			t.Fatalf("hook order %v", got)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	for range runTurn(ctx, scripted{}, engine.Request{}, func(kind string, _ engine.Event) error {
		if kind == "abort" {
			close(done)
		}
		return nil
	}) {
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not emit abort")
	}
}

func TestWarRoomSnapshotPollingIsAsyncAndRejectsStale(t *testing.T) {
	m := warFixture(100, 30)
	calls := 0
	m.setupCfg = &Setup{WarRoom: &WarRoomServices{Catalog: func() []arsenal.Capability { calls++; return nil }}}
	cmd := m.pollWarRoom()
	if calls != 0 || cmd == nil {
		t.Fatal("catalog called in Update")
	}
	msg := cmd().(warSnapshotMsg)
	if calls != 1 {
		t.Fatal("catalog not polled")
	}
	m.resetWarSnapshot()
	m, _ = m.onWarSnapshot(msg)
	if m.war.haveSnapshot {
		t.Fatal("stale snapshot restored old engine")
	}
	m.war.jobID = 2
	m.war.busy = true
	m, _ = m.onWarResult(warResultMsg{id: 1, err: errors.New("stale")})
	if !m.war.busy || m.war.err != "" {
		t.Fatal("stale action changed state")
	}
}

type controlledEngine struct {
	inspectingEngine
	paused, resumed *int
}

func (e controlledEngine) PauseMission(string) error  { *e.paused++; return nil }
func (e controlledEngine) ResumeMission(string) error { *e.resumed++; return nil }

func TestWarRoomPauseAndResumeDoNotCancelBenchmark(t *testing.T) {
	m := warFixture(120, 34)
	paused, resumed := 0, 0
	m.eng = controlledEngine{inspectingEngine: m.eng.(inspectingEngine), paused: &paused, resumed: &resumed}
	m.war.busy = true
	m.war.jobID = 7
	m, cmd := press(m, ' ')
	if cmd == nil || paused != 0 {
		t.Fatal("pause must be an asynchronous control action")
	}
	next, _ := m.Update(cmd())
	m = next.(Model)
	if paused != 1 || !m.war.busy || m.war.jobID != 7 {
		t.Fatal("pause disturbed the background operation")
	}
	m.war.snapshot.Status = mission.Paused
	m, cmd = press(m, ' ')
	next, _ = m.Update(cmd())
	m = next.(Model)
	if resumed != 1 || !m.war.busy {
		t.Fatal("resume disturbed background operation")
	}
	m.war.composing = true
	m.input.Focus()
	m = typeText(m, " ")
	if paused != 1 || resumed != 1 || m.input.Value() != " " {
		t.Fatal("space in focused input controlled mission")
	}
}

// Optional deterministic frames let developers inspect the exact composed
// output without starting a provider or running security tools.
func TestWarRoomPreview(t *testing.T) {
	dir := os.Getenv("ROGUE_WARROOM_PREVIEW")
	if dir == "" {
		t.Skip("set ROGUE_WARROOM_PREVIEW to save terminal frames")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, sz := range [][2]int{{60, 16}, {100, 30}, {140, 38}, {200, 50}} {
		for tab := range warTabs {
			m := warFixture(sz[0], sz[1])
			m.war.tab = tab
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%dx%d-%d.ansi", sz[0], sz[1], tab+1)), []byte(m.View().Content), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	m := warFixture(100, 30)
	m.war.approvals = []approvalMsg{{request: engine.ApprovalRequest{MissionID: "mission-7f32", Tool: "nmap_scan", Target: "127.0.0.1", Arguments: json.RawMessage(`{"host":"127.0.0.1","ports":[80,443,3000],"service_detection":true}`)}}}
	if err := os.WriteFile(filepath.Join(dir, "approval.ansi"), []byte(m.View().Content), 0600); err != nil {
		t.Fatal(err)
	}
}
