package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"rogue/internal/engine"
)

// Credentials is what the setup screen collects. An empty APIKey means "use
// the key that is already available" (saved file or environment).
type Credentials struct {
	Provider, APIKey, Model string
	Remember                bool
}

// ProviderChoice is one row of the provider picker.
type ProviderChoice struct {
	Name, Label string
	KeyEnv      string // empty for keyless providers such as ollama
	ModelHint   string
	Existing    string // e.g. "saved sk-…a1b2" or "from $OPENAI_API_KEY"; empty if none
}

// SetupOptions is a fresh snapshot of what is configured, taken every time
// the screen opens so saved-key hints never go stale.
type SetupOptions struct {
	Providers       []ProviderChoice
	Provider, Model string // prefill
	SavePath        string // empty when saving is disabled
	Warning         string // e.g. an unreadable credentials file
}

// Setup wires the screen to the outside world. The TUI never touches files or
// the network itself: main supplies both callbacks.
type Setup struct {
	Reason  string // why setup opened at startup
	Options func() SetupOptions
	Connect func(Credentials) (engine.Engine, error)
}

type setupStep int

const (
	stepProvider setupStep = iota
	stepKey
	stepModel
	stepSave
	stepConnecting
)

type setupState struct {
	opts     SetupOptions
	step     setupStep
	idx      int // provider row
	saveIdx  int // 0 = save, 1 = session only
	key      textinput.Model
	model    textinput.Model
	err      string
	returnTo phase // where esc on the first step goes; phaseSetup = nowhere
}

// connectedMsg returns the result of Setup.Connect from a tea.Cmd, so building
// the harness never blocks the render loop.
type connectedMsg struct {
	eng   engine.Engine
	err   error
	creds Credentials
}

func newSetupInput(placeholder string, secret bool) textinput.Model {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.Placeholder = placeholder
	ti.CharLimit = 512
	if secret {
		ti.EchoMode = textinput.EchoPassword
		ti.EchoCharacter = '•'
	}
	s := textinput.DefaultDarkStyles()
	for _, st := range []*textinput.StyleState{&s.Focused, &s.Blurred} {
		st.Text = fg(colText)
		st.Placeholder = fg(colDim)
		st.Prompt = fg(colPrompt).Bold(true)
	}
	s.Cursor.Color = colPrompt
	s.Cursor.Blink = false
	ti.SetStyles(s)
	return ti
}

// openSetup shows the setup screen. From a running session, esc returns there.
func (m *Model) openSetup() tea.Cmd {
	if m.setupCfg == nil || m.setupCfg.Connect == nil {
		m.notice("provider setup is not available in this build")
		return nil
	}
	m.stopTurn()
	opts := SetupOptions{}
	if m.setupCfg.Options != nil {
		opts = m.setupCfg.Options()
	}
	if m.provider != "" { // what we connected with beats the startup snapshot
		opts.Provider, opts.Model = m.provider, m.model
	}
	s := &setupState{opts: opts, returnTo: phaseSetup, key: newSetupInput("", true), model: newSetupInput("", false)}
	if m.eng != nil {
		s.returnTo = m.phase
	}
	for i, p := range opts.Providers {
		if p.Name == opts.Provider {
			s.idx = i
		}
	}
	m.setup = s
	m.phase = phaseSetup
	return nil
}

func (s *setupState) choice() ProviderChoice {
	if len(s.opts.Providers) == 0 {
		return ProviderChoice{}
	}
	return s.opts.Providers[s.idx]
}

func (m Model) onSetupKey(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	s := m.setup
	k := msg.String()
	if s.step == stepConnecting {
		return m, nil
	}
	if k == "esc" {
		s.err = ""
		switch s.step {
		case stepProvider:
			if s.returnTo != phaseSetup {
				m.phase, m.setup = s.returnTo, nil
			}
		case stepKey:
			s.step = stepProvider
		case stepModel:
			if s.choice().KeyEnv != "" {
				s.step = stepKey
			} else {
				s.step = stepProvider
			}
		case stepSave:
			s.step = stepModel
		}
		return m, nil
	}

	switch s.step {
	case stepProvider:
		n := len(s.opts.Providers)
		switch {
		case k == "up" || k == "k":
			s.idx = max(0, s.idx-1)
		case k == "down" || k == "j":
			s.idx = min(n-1, s.idx+1)
		case len(k) == 1 && k[0] >= '1' && k[0] <= '9' && int(k[0]-'1') < n:
			s.idx = int(k[0] - '1')
			return m, s.pickProvider()
		case k == "enter" && n > 0:
			return m, s.pickProvider()
		}
		return m, nil

	case stepKey:
		if k == "enter" {
			key := strings.TrimSpace(s.key.Value())
			if key == "" && s.choice().Existing == "" {
				s.err = "paste your " + s.choice().KeyEnv
				return m, nil
			}
			if strings.ContainsAny(key, " \t") {
				s.err = "an API key has no spaces · check what was pasted"
				return m, nil
			}
			s.err = ""
			return m, s.toModel()
		}
		var cmd tea.Cmd
		s.key, cmd = s.key.Update(msg)
		return m, cmd

	case stepModel:
		if k == "enter" {
			if strings.TrimSpace(s.model.Value()) == "" {
				s.err = "enter a model id"
				return m, nil
			}
			s.err = ""
			if s.opts.SavePath == "" {
				return m, m.connect(false)
			}
			s.step = stepSave
			return m, nil
		}
		var cmd tea.Cmd
		s.model, cmd = s.model.Update(msg)
		return m, cmd

	case stepSave:
		switch k {
		case "up", "k":
			s.saveIdx = 0
		case "down", "j":
			s.saveIdx = 1
		case "y":
			return m, m.connect(true)
		case "n":
			return m, m.connect(false)
		case "enter":
			return m, m.connect(s.saveIdx == 0)
		}
	}
	return m, nil
}

func (s *setupState) pickProvider() tea.Cmd {
	s.err = ""
	c := s.choice()
	if c.KeyEnv == "" {
		return s.toModel()
	}
	s.step = stepKey
	s.key.Reset()
	s.key.Placeholder = "paste " + c.KeyEnv
	if c.Existing != "" {
		s.key.Placeholder = "↵ keep " + c.Existing
	}
	s.model.Blur()
	return s.key.Focus()
}

func (s *setupState) toModel() tea.Cmd {
	c := s.choice()
	s.step = stepModel
	s.model.Placeholder = c.ModelHint
	if s.model.Value() == "" || s.opts.Provider != c.Name {
		s.model.Reset()
		if c.Name == s.opts.Provider {
			s.model.SetValue(s.opts.Model)
			s.model.CursorEnd()
		}
	}
	s.key.Blur()
	return s.model.Focus()
}

func (m *Model) connect(remember bool) tea.Cmd {
	s := m.setup
	creds := Credentials{
		Provider: s.choice().Name,
		APIKey:   strings.TrimSpace(s.key.Value()),
		Model:    strings.TrimSpace(s.model.Value()),
		Remember: remember,
	}
	if s.choice().KeyEnv == "" {
		creds.APIKey = ""
	}
	s.step = stepConnecting
	connect := m.setupCfg.Connect
	return tea.Batch(m.spin.Tick, func() tea.Msg {
		eng, err := connect(creds)
		return connectedMsg{eng: eng, err: err, creds: creds}
	})
}

func (m Model) onConnected(msg connectedMsg) (Model, tea.Cmd) {
	s := m.setup
	if s == nil {
		return m, nil
	}
	if msg.eng == nil {
		s.step = stepModel
		s.err = "could not connect: " + errText(msg.err)
		return m, s.model.Focus()
	}
	m.stopTurn()
	m.eng = msg.eng
	m.provider = msg.creds.Provider
	m.model = msg.creds.Model
	if ms := m.eng.Models(); len(ms) > 0 {
		m.model = ms[0]
	}
	m.setupCfg.Reason = ""
	next := s.returnTo
	if next == phaseSetup {
		next = phaseLanding
	}
	m.setup, m.phase = nil, next
	m.input.Focus()
	m.notice("connected · " + msg.creds.Provider + " · " + m.model)
	if msg.err != nil { // connected, but saving failed
		m.notice(errText(msg.err))
	} else if msg.creds.Remember {
		m.notice("saved to " + s.opts.SavePath + " (owner-only)")
	}
	return m, nil
}

func errText(err error) string {
	if err == nil {
		return "unknown error"
	}
	return err.Error()
}

// ── view ─────────────────────────────────────────────────────────────────────

func (m Model) viewSetup() string {
	s := m.setup
	w := min(m.workWidth(), 72)
	wrap := func(st lipgloss.Style, text string) string {
		return st.Render(ansi.Wrap(text, w, ""))
	}
	parts := []string{stLogo.Render("◆ ROGUE"), stMuted.Render("connect a model provider"), ""}
	if m.setupCfg.Reason != "" && s.step == stepProvider {
		parts = append(parts, wrap(stDim, m.setupCfg.Reason), "")
	}
	if s.opts.Warning != "" {
		parts = append(parts, wrap(stYellow, "! "+s.opts.Warning), "")
	}
	parts = append(parts, m.setupCrumbs(), "")

	c := s.choice()
	var hint string
	switch s.step {
	case stepProvider:
		rows := []string{}
		for i, p := range s.opts.Providers {
			line := fmt.Sprintf("%d  %s", i+1, padRight(p.Label, 24))
			if p.Existing != "" {
				line += p.Existing
			}
			line = ansi.Truncate(line, w-2, "…")
			if i == s.idx {
				rows = append(rows, lipgloss.NewStyle().Background(colSelected).Foreground(colLogo).Bold(true).Width(w).Render("› "+line))
			} else {
				rows = append(rows, stText.Render("  "+line))
			}
		}
		parts = append(parts, lipgloss.NewStyle().Width(w).Render(strings.Join(rows, "\n")))
		hint = "↑↓ choose  ·  ↵ next"
		if s.returnTo != phaseSetup {
			hint += "  ·  esc cancel"
		}
	case stepKey:
		parts = append(parts, stMuted.Render(c.Label+" API key"), m.setupBox(s.key.View(), w))
		note := "input is masked · nothing is written until you choose to save"
		parts = append(parts, wrap(stDim, note))
		hint = "↵ next  ·  esc back"
	case stepModel:
		parts = append(parts, stMuted.Render(c.Label+" model"), m.setupBox(s.model.View(), w))
		if c.ModelHint != "" {
			parts = append(parts, wrap(stDim, c.ModelHint))
		}
		hint = "↵ next  ·  esc back"
	case stepSave:
		opts := []string{"save on this machine", "use for this session only"}
		rows := []string{}
		for i, o := range opts {
			if i == s.saveIdx {
				rows = append(rows, lipgloss.NewStyle().Background(colSelected).Foreground(colLogo).Bold(true).Width(w).Render("› "+o))
			} else {
				rows = append(rows, stText.Render("  "+o))
			}
		}
		parts = append(parts, lipgloss.NewStyle().Width(w).Render(strings.Join(rows, "\n")), "",
			wrap(stDim, "saved to "+s.opts.SavePath+" with 0600 permissions; environment variables still take precedence"))
		hint = "↑↓ choose  ·  ↵ connect  ·  esc back"
	case stepConnecting:
		parts = append(parts, m.spin.View()+" "+stMuted.Render("connecting to "+c.Label+"…"))
	}
	parts = append(parts, "")
	if s.err != "" {
		parts = append(parts, wrap(stRed, s.err))
	} else if hint != "" {
		parts = append(parts, stDim.Render(hint))
	}
	block := lipgloss.NewStyle().Width(w).Render(lipgloss.JoinVertical(lipgloss.Left, parts...))
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, block)
}

func (m Model) setupCrumbs() string {
	s := m.setup
	type crumb struct {
		name string
		step setupStep
	}
	crumbs := []crumb{{"provider", stepProvider}}
	if s.choice().KeyEnv != "" {
		crumbs = append(crumbs, crumb{"key", stepKey})
	}
	crumbs = append(crumbs, crumb{"model", stepModel})
	if s.opts.SavePath != "" {
		crumbs = append(crumbs, crumb{"save", stepSave})
	}
	out := []string{}
	for _, c := range crumbs {
		switch {
		case c.step == s.step:
			out = append(out, stLogo.Render(c.name))
		case c.step < s.step:
			out = append(out, stMuted.Render(c.name))
		default:
			out = append(out, stDim.Render(c.name))
		}
	}
	return strings.Join(out, stDim.Render("  ›  "))
}

func (m Model) setupBox(content string, w int) string {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colAccent).
		Padding(0, 1).
		Width(w).
		Render(content)
}
