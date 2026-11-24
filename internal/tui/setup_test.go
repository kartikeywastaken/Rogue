package tui

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"rogue/internal/engine"
)

func testSetup(got *[]Credentials, fail bool) *Setup {
	return &Setup{
		Reason: "no usable provider yet",
		Options: func() SetupOptions {
			return SetupOptions{
				SavePath: "/tmp/rogue-test/credentials.json",
				Providers: []ProviderChoice{
					{Name: "openrouter", Label: "OpenRouter", KeyEnv: "OPENROUTER_API_KEY", ModelHint: "vendor/model"},
					{Name: "anthropic", Label: "Anthropic", KeyEnv: "ANTHROPIC_API_KEY", Existing: "saved sk-…1234"},
					{Name: "ollama", Label: "Ollama"},
				},
			}
		},
		Connect: func(c Credentials) (engine.Engine, error) {
			*got = append(*got, c)
			if fail {
				return nil, errors.New("ROGUE_MODEL is required")
			}
			return scripted{}, nil
		},
	}
}

// run executes a Cmd tree synchronously, feeding connectedMsg back in.
func run(m Model, cmd tea.Cmd) Model {
	if cmd == nil {
		return m
	}
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		for _, c := range msg {
			m = run(m, c)
		}
	case connectedMsg:
		next, _ := m.Update(msg)
		m = next.(Model)
	}
	return m
}

func paste(m Model, s string) Model {
	next, _ := m.Update(tea.PasteMsg{Content: s})
	return next.(Model)
}

func TestSetupOpensWithoutEngineAndSavesKey(t *testing.T) {
	var got []Credentials
	next, _ := NewWithSetup(nil, testSetup(&got, false)).Update(tea.WindowSizeMsg{Width: 90, Height: 30})
	m := next.(Model)
	if m.phase != phaseSetup || !strings.Contains(frame(m), "connect a model provider") {
		t.Fatal("did not open on setup", frame(m))
	}
	checkFrame(t, m, 90, 30)
	m, _ = press(m, tea.KeyEnter) // OpenRouter
	if m.setup.step != stepKey {
		t.Fatal("expected key step")
	}
	m, _ = press(m, tea.KeyEnter)
	if !strings.Contains(m.setup.err, "OPENROUTER_API_KEY") {
		t.Fatal("empty key accepted")
	}
	m = paste(m, "  sk-or-secret-value-9876\n")
	if f := frame(m); strings.Contains(f, "secret") || !strings.Contains(f, "•••") {
		t.Fatal("key not masked on screen:\n" + f)
	}
	m, _ = press(m, tea.KeyEnter)
	m = typeText(m, "vendor/model-a")
	m, _ = press(m, tea.KeyEnter)
	if m.setup.step != stepSave {
		t.Fatal("expected save step")
	}
	checkFrame(t, m, 90, 30)
	m, cmd := press(m, tea.KeyEnter) // default: save
	m = run(m, cmd)
	if len(got) != 1 || got[0] != (Credentials{Provider: "openrouter", APIKey: "sk-or-secret-value-9876", Model: "vendor/model-a", Remember: true}) {
		t.Fatalf("%+v", got)
	}
	if m.phase != phaseLanding || m.eng == nil || m.setup != nil || !strings.Contains(m.flash, "saved to") {
		t.Fatal("did not land after connect", m.phase, m.flash)
	}
}

func TestSetupKeepsSavedKeyKeylessAndErrors(t *testing.T) {
	var got []Credentials
	m := NewWithSetup(nil, testSetup(&got, true))
	next, _ := m.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	m = next.(Model)
	m = typeText(m, "2") // Anthropic, has a saved key
	m, _ = press(m, tea.KeyEnter)
	if m.setup.step != stepModel {
		t.Fatal("blank key should keep the saved one")
	}
	m = typeText(m, "claude-x")
	m, _ = press(m, tea.KeyEnter)
	m, cmd := press(m, 'n') // session only
	m = run(m, cmd)
	if got[0].APIKey != "" || got[0].Remember {
		t.Fatalf("%+v", got[0])
	}
	if m.phase != phaseSetup || !strings.Contains(m.setup.err, "could not connect") {
		t.Fatal("connect failure not shown")
	}
	checkFrame(t, m, 60, 20)
	// esc walks back; with no engine the first step cannot be escaped.
	for range 4 {
		m, _ = press(m, tea.KeyEscape)
	}
	if m.phase != phaseSetup || m.setup.step != stepProvider {
		t.Fatal("escaped setup with no engine")
	}
	m = typeText(m, "3") // Ollama skips the key step
	if m.setup.step != stepModel {
		t.Fatal("keyless provider asked for a key")
	}
}

func TestProviderCommandFromSession(t *testing.T) {
	var got []Credentials
	m := NewWithSetup(scripted{}, testSetup(&got, false))
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = next.(Model)
	m = typeText(m, "/provider")
	m, _ = press(m, tea.KeyEnter)
	if m.phase != phaseSetup {
		t.Fatal("/provider did not open setup")
	}
	m, _ = press(m, tea.KeyEscape)
	if m.phase != phaseLanding || m.setup != nil {
		t.Fatal("esc did not return to the landing screen")
	}
	plain := New(scripted{})
	plain = typeText(plain, "/provider")
	plain, _ = press(plain, tea.KeyEnter)
	if plain.phase == phaseSetup {
		t.Fatal("plain New has no setup to open")
	}
}
