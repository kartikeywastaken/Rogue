package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"rogue/internal/engine"
)

// fixed is an engine configured with exactly the given models.
type fixed struct{ models []string }

func (fixed) Name() string       { return "fixed" }
func (f fixed) Models() []string { return append([]string(nil), f.models...) }
func (fixed) Run(context.Context, engine.Request) <-chan engine.Event {
	ch := make(chan engine.Event)
	close(ch)
	return ch
}

// deliver runs a Cmd tree synchronously, feeding picker/switch replies back in.
func deliver(m Model, cmd tea.Cmd) Model {
	if cmd == nil {
		return m
	}
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		for _, c := range msg {
			m = deliver(m, c)
		}
	case pickerModelsMsg, modelSwitchedMsg:
		next, _ := m.Update(msg)
		m = next.(Model)
	}
	return m
}

func pickerSetup(connected *[]Credentials, catalog []string, catalogErr error) *Setup {
	return &Setup{
		Current: Credentials{Provider: "gemini", Model: "gemini-4-carbon", Remember: true},
		Options: func() SetupOptions { return SetupOptions{} },
		ListModels: func(c Credentials) ([]string, error) {
			if c.Provider != "gemini" || c.Model != "" {
				return nil, errors.New("wrong catalog request")
			}
			return catalog, catalogErr
		},
		Connect: func(c Credentials) (engine.Engine, error) {
			*connected = append(*connected, c)
			if c.Model == "broken" {
				return nil, errors.New("ROGUE_MODEL rejected")
			}
			return fixed{models: []string{c.Model}}, nil
		},
	}
}

func openModel(t *testing.T, m Model) (Model, tea.Cmd) {
	t.Helper()
	m = typeText(m, "/model")
	m, cmd := press(m, tea.KeyEnter)
	if !m.picker {
		t.Fatal("/model did not open the picker")
	}
	return m, cmd
}

func TestModelPickerLoadsCatalogAndSwitchesEngine(t *testing.T) {
	var connected []Credentials
	cfg := pickerSetup(&connected, []string{"gemini-4-flash", "gemini-4-carbon", "gemini-4-flash-lite"}, nil)
	next, _ := NewWithSetup(fixed{models: []string{"gemini-4-carbon"}}, cfg).Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m := next.(Model)
	m, cmd := openModel(t, m)
	if !m.pickLoading || !strings.Contains(frame(m), "loading the provider's models") {
		t.Fatal("catalog not loading")
	}
	m = deliver(m, cmd)
	f := frame(m)
	if !strings.Contains(f, "gemini-4-flash-lite") || strings.Count(f, "gemini-4-carbon") < 1 {
		t.Fatal("catalog not shown:\n" + f)
	}
	if len(m.pickList) != 3 || m.pickList[0] != "gemini-4-carbon" {
		t.Fatal("configured model should stay first, no duplicates:", m.pickList)
	}
	checkFrame(t, m, 100, 30)
	m = typeText(m, "lite") // digits and letters filter now
	if got := m.pickMatches(); len(got) != 1 || got[0] != "gemini-4-flash-lite" {
		t.Fatal("filter wrong", got)
	}
	m, cmd = press(m, tea.KeyEnter)
	if !m.switching || m.picker {
		t.Fatal("did not start switching")
	}
	m, _ = press(m, tea.KeyEnter) // submit while switching is refused
	m = deliver(m, cmd)
	if len(connected) != 1 || connected[0] != (Credentials{Provider: "gemini", Model: "gemini-4-flash-lite", Remember: true}) {
		t.Fatalf("connect called with %+v", connected)
	}
	if m.switching || m.model != "gemini-4-flash-lite" || m.eng.Models()[0] != "gemini-4-flash-lite" {
		t.Fatal("engine not swapped", m.model)
	}
	if !strings.Contains(frame(m), "saved as the default model") {
		t.Fatal("no confirmation")
	}
	// Picking the now-configured model is instant: no new engine.
	m, cmd = openModel(t, m)
	m = deliver(m, cmd)
	m = typeText(m, "flash-lite")
	m, _ = press(m, tea.KeyEnter)
	if len(connected) != 1 || m.switching {
		t.Fatal("configured model needlessly rebuilt the engine")
	}
}

func TestModelPickerFailuresAndStaleReplies(t *testing.T) {
	var connected []Credentials
	cfg := pickerSetup(&connected, nil, errors.New("gemini HTTP 401: the provider rejected this API key"))
	next, _ := NewWithSetup(fixed{models: []string{"gemini-4-carbon"}}, cfg).Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m := next.(Model)
	m, cmd := openModel(t, m)
	seq := m.pickSeq
	m = deliver(m, cmd)
	if !strings.Contains(frame(m), "catalog unavailable") {
		t.Fatal("catalog error not shown:\n" + frame(m))
	}
	checkFrame(t, m, 80, 24)
	next, _ = m.Update(pickerModelsMsg{seq: seq - 1, models: []string{"stale"}})
	if m = next.(Model); len(m.pickList) != 1 {
		t.Fatal("stale catalog applied")
	}
	// An unlisted typed id is still tried, and a failure is reported.
	m = typeText(m, "broken")
	m, cmd = press(m, tea.KeyEnter)
	m = deliver(m, cmd)
	if m.model != "gemini-4-carbon" || m.switching || !strings.Contains(frame(m), "could not switch to broken") {
		t.Fatal("failed switch not handled:\n" + frame(m))
	}
	// Plain New (no setup): picker still offers configured models only.
	plain := sized(scripted{}, 80, 24)
	plain, _ = openModel(t, plain)
	plain = typeText(plain, "unlisted")
	plain, _ = press(plain, tea.KeyEnter)
	if !strings.Contains(plain.flash, "not configured") {
		t.Fatal("unconfigured model accepted without setup", plain.flash)
	}
}

func TestQuotaErrorSuggestsModelSwitch(t *testing.T) {
	eng := scripted{events: []engine.Event{{Kind: engine.KindError, Err: errors.New(`coordinator: model request: gemini HTTP 429: quota exceeded`)}}}
	m := sized(eng, 100, 30)
	m = typeText(m, "scan it")
	m, _ = press(m, tea.KeyEnter)
	m = drain(t, m)
	if !strings.Contains(frame(m), "/model to pick another") {
		t.Fatal("no hint after 429:\n" + frame(m))
	}
}
