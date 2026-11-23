package tui

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"rogue/internal/engine"
)

// scripted is an instant engine so tests don't depend on the mock's timing.
type scripted struct{ events []engine.Event }

func (scripted) Name() string     { return "test" }
func (scripted) Models() []string { return []string{"m-one", "m-two"} }
func (s scripted) Run(ctx context.Context, _ engine.Request) <-chan engine.Event {
	ch := make(chan engine.Event, len(s.events))
	for _, e := range s.events {
		ch <- e
	}
	close(ch)
	return ch
}

func typeText(m Model, s string) Model {
	for _, r := range s {
		next, _ := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
		m = next.(Model)
	}
	return m
}

func press(m Model, code rune, mod ...tea.KeyMod) (Model, tea.Cmd) {
	k := tea.KeyPressMsg{Code: code}
	if len(mod) > 0 {
		k.Mod = mod[0]
	}
	next, cmd := m.Update(k)
	return next.(Model), cmd
}

func sized(eng engine.Engine, w, h int) Model {
	next, _ := New(eng).Update(tea.WindowSizeMsg{Width: w, Height: h})
	return next.(Model)
}

// drain feeds every engine event back through Update until the turn ends.
func drain(t *testing.T, m Model) Model {
	t.Helper()
	for i := 0; m.running && i < 100; i++ {
		next, _ := m.Update(waitFor(m.events)())
		m = next.(Model)
	}
	if m.running {
		t.Fatal("turn never finished")
	}
	return m
}

func frame(m Model) string { return ansi.Strip(m.View().Content) }

func checkFrame(t *testing.T, m Model, w, h int) {
	t.Helper()
	f := m.View().Content
	lines := strings.Split(f, "\n")
	if len(lines) > h {
		t.Fatalf("frame has %d lines, terminal is %d", len(lines), h)
	}
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			t.Fatalf("line %d is %d wide, terminal is %d", i, lipgloss.Width(l), w)
		}
	}
	if os.Getenv("ROGUE_DUMP") != "" {
		t.Logf("\n%s", ansi.Strip(f))
	}
}

func TestLandingFitsAllSizes(t *testing.T) {
	for _, sz := range [][2]int{{60, 16}, {110, 34}, {200, 50}, {28, 10}} {
		m := sized(scripted{}, sz[0], sz[1])
		checkFrame(t, m, sz[0], sz[1])
		if m.phase != phaseLanding {
			t.Fatal("should open on landing")
		}
	}
}

func TestSubmitStreamsIntoSession(t *testing.T) {
	eng := scripted{events: []engine.Event{
		{Kind: engine.KindText, Text: "Reading "},
		{Kind: engine.KindToolStart, Tool: engine.ToolCall{ID: "a", Name: "read_file", Input: "main.go"}},
		{Kind: engine.KindToolEnd, Tool: engine.ToolCall{ID: "a", Name: "read_file", Input: "main.go", Output: "20 lines", OK: true}},
		{Kind: engine.KindText, Text: "done."},
		{Kind: engine.KindUsage, Usage: engine.Usage{Input: 10, Output: 1500}},
		{Kind: engine.KindDone},
	}}
	m := sized(eng, 110, 34)
	m = typeText(m, "hello rogue")
	m, _ = press(m, tea.KeyEnter)
	if m.phase != phaseSession || !m.running {
		t.Fatal("enter should start a turn in the session view")
	}
	m = drain(t, m)
	checkFrame(t, m, 110, 34)
	f := frame(m)
	for _, want := range []string{"› hello rogue", "◆ Reading", "read_file main.go", "└ 20 lines", "◆ done."} {
		if !strings.Contains(f, want) {
			t.Errorf("frame missing %q", want)
		}
	}
}

func TestSlashPaletteAndCommands(t *testing.T) {
	m := sized(scripted{}, 110, 34)
	m = typeText(m, "/mo")
	f := frame(m)
	if !strings.Contains(f, "/model") || !strings.Contains(f, "/mode") || strings.Contains(f, "/quit") {
		t.Fatalf("palette should filter to /model and /mode:\n%s", f)
	}
	checkFrame(t, m, 110, 34)

	m, _ = press(m, tea.KeyEnter) // highlighted: /model
	if !m.picker {
		t.Fatal("/model should open the picker")
	}
	m, _ = press(m, tea.KeyDown)
	m, _ = press(m, tea.KeyEnter)
	if m.model != "m-two" {
		t.Fatalf("model = %q", m.model)
	}

	m, _ = press(m, tea.KeyTab, tea.ModShift)
	if m.mode != engine.ModeAuto {
		t.Fatalf("shift+tab should cycle mode, got %v", m.mode)
	}

	m = typeText(m, "/nope")
	m, _ = press(m, tea.KeyEnter)
	if !strings.Contains(m.flash, "unknown command") {
		t.Fatal("unknown command should flash inline")
	}
}

func TestEscInterruptsAndDropsStaleEvents(t *testing.T) {
	m := sized(engine.NewMock(), 110, 34)
	m = typeText(m, "go")
	m, _ = press(m, tea.KeyEnter)
	old := m.events
	m, _ = press(m, tea.KeyEscape)
	if m.running {
		t.Fatal("esc should stop the turn")
	}
	next, _ := m.Update(eventMsg{ch: old, ev: engine.Event{Kind: engine.KindText, Text: "late"}, ok: true})
	if strings.Contains(frame(next.(Model)), "late") {
		t.Fatal("events from an interrupted turn must be ignored")
	}
}

func TestMockSessionFrame(t *testing.T) {
	m := sized(engine.NewMock(), 110, 34)
	m = typeText(m, "what's in this repo?")
	m, _ = press(m, tea.KeyEnter)
	deadline := time.After(10 * time.Second)
	for m.running {
		select {
		case <-deadline:
			t.Fatal("mock turn too slow")
		default:
		}
		next, _ := m.Update(waitFor(m.events)())
		m = next.(Model)
	}
	checkFrame(t, m, 110, 34)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 60, Height: 16})
	checkFrame(t, next.(Model), 60, 16)
}
