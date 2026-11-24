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
	BaseURL                 string // only for providers that need one
	Remember                bool
}

// ProviderChoice is one row of the provider picker.
type ProviderChoice struct {
	Name, Label string
	KeyEnv      string // empty for keyless providers such as ollama
	ModelHint   string
	KeyOptional bool   // an empty key is allowed
	NeedsURL    bool   // ask for the endpoint's base URL first
	Existing    string // e.g. "saved sk-…a1b2" or "from $OPENAI_API_KEY"; empty if none
}

// SetupOptions is a fresh snapshot of what is configured, taken every time
// the screen opens so saved-key hints never go stale.
type SetupOptions struct {
	Providers       []ProviderChoice
	Provider, Model string // prefill
	BaseURL         string // prefill for providers that need one
	SavePath        string // empty when saving is disabled
	Warning         string // e.g. an unreadable credentials file
}

// Setup wires the screen to the outside world. The TUI never touches files or
// the network itself: main supplies the callbacks.
type Setup struct {
	Reason  string // why setup opened at startup
	Options func() SetupOptions
	Connect func(Credentials) (engine.Engine, error)
	// ListModels returns the provider's catalog for the entered key (optional).
	// Model is empty in the Credentials it receives.
	ListModels func(Credentials) ([]string, error)
}

type setupStep int

const (
	stepProvider setupStep = iota
	stepURL
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
	url      textinput.Model
	key      textinput.Model
	model    textinput.Model
	err      string
	returnTo phase // where esc on the first step goes; phaseSetup = nowhere

	// model catalog for the model step
	list      func(Credentials) ([]string, error)
	tick      tea.Cmd // spinner tick, so setupState can start the spinner itself
	seq       int     // identifies the latest catalog request; older replies are dropped
	loading   bool
	models    []string
	modelsErr string
	pick      int  // highlighted row among matches()
	filtering bool // the user has typed, so the input filters the list
	navigated bool // the user moved the highlight with ↑↓
}

// modelsMsg carries a catalog reply back onto the Elm loop.
type modelsMsg struct {
	seq    int
	models []string
	err    error
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
	s := &setupState{opts: opts, returnTo: phaseSetup, url: newSetupInput("https://host/v1", false), key: newSetupInput("", true), model: newSetupInput("", false)}
	if m.baseURL != "" {
		opts.BaseURL = m.baseURL
	}
	s.url.SetValue(opts.BaseURL)
	s.opts = opts
	s.list, s.tick = m.setupCfg.ListModels, m.spin.Tick
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
		case stepURL:
			s.step = stepProvider
		case stepKey:
			if s.choice().NeedsURL {
				s.step = stepURL
				return m, s.focus(&s.url)
			}
			s.step = stepProvider
		case stepModel:
			switch {
			case s.choice().KeyEnv != "":
				s.step = stepKey
				return m, s.focus(&s.key)
			case s.choice().NeedsURL:
				s.step = stepURL
				return m, s.focus(&s.url)
			default:
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

	case stepURL:
		if k == "enter" {
			u := strings.TrimSpace(s.url.Value())
			if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
				s.err = "enter the endpoint's base URL, e.g. https://host/v1"
				return m, nil
			}
			s.err = ""
			return m, s.toKey()
		}
		var cmd tea.Cmd
		s.url, cmd = s.url.Update(msg)
		return m, cmd

	case stepKey:
		if k == "enter" {
			key := strings.TrimSpace(s.key.Value())
			if key == "" && s.choice().Existing == "" && !s.choice().KeyOptional {
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
		switch k {
		case "up":
			s.pick, s.navigated = max(0, s.pick-1), true
			return m, nil
		case "down":
			s.pick, s.navigated = min(max(0, len(s.matches())-1), s.pick+1), true
			return m, nil
		case "tab":
			if id := s.highlighted(); id != "" {
				s.model.SetValue(id)
				s.model.CursorEnd()
				s.filtering, s.pick = false, s.indexOf(id)
			}
			return m, nil
		}
		if k == "enter" {
			// An untouched prefill (the saved model) wins over the highlight,
			// even when the catalog does not list it.
			untouched := !s.filtering && !s.navigated && strings.TrimSpace(s.model.Value()) != ""
			if id := s.highlighted(); id != "" && !untouched {
				s.model.SetValue(id)
			}
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
		prev := s.model.Value()
		var cmd tea.Cmd
		s.model, cmd = s.model.Update(msg)
		if s.model.Value() != prev {
			s.filtering, s.pick = true, 0
		}
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
	if s.choice().NeedsURL {
		s.step = stepURL
		return s.focus(&s.url)
	}
	return s.toKey()
}

func (s *setupState) toKey() tea.Cmd {
	c := s.choice()
	if c.KeyEnv == "" {
		return s.toModel()
	}
	s.step = stepKey
	s.key.Reset()
	switch {
	case c.Existing != "":
		s.key.Placeholder = "↵ keep " + c.Existing
	case c.KeyOptional:
		s.key.Placeholder = "optional · ↵ if the endpoint needs no key"
	default:
		s.key.Placeholder = "paste " + c.KeyEnv
	}
	return s.focus(&s.key)
}

// focus focuses exactly one setup input.
func (s *setupState) focus(target *textinput.Model) tea.Cmd {
	for _, ti := range []*textinput.Model{&s.url, &s.key, &s.model} {
		if ti != target {
			ti.Blur()
		}
	}
	return target.Focus()
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
	s.filtering, s.navigated, s.pick = false, false, 0
	return tea.Batch(s.focus(&s.model), s.fetchModels())
}

// creds snapshots what has been entered so far.
func (s *setupState) creds() Credentials {
	c := s.choice()
	creds := Credentials{Provider: c.Name, Model: strings.TrimSpace(s.model.Value())}
	if c.KeyEnv != "" {
		creds.APIKey = strings.TrimSpace(s.key.Value())
	}
	if c.NeedsURL {
		creds.BaseURL = strings.TrimRight(strings.TrimSpace(s.url.Value()), "/")
	}
	return creds
}

// fetchModels asks for the catalog in the background. Every call bumps seq,
// so a slow reply for a provider the user has since left is ignored.
func (s *setupState) fetchModels() tea.Cmd {
	s.seq++
	s.models, s.modelsErr = nil, ""
	if s.list == nil {
		s.loading = false
		return nil
	}
	s.loading = true
	seq, list, creds := s.seq, s.list, s.creds()
	creds.Model = ""
	return tea.Batch(s.tick, func() tea.Msg {
		models, err := list(creds)
		return modelsMsg{seq: seq, models: models, err: err}
	})
}

func (m Model) onModels(msg modelsMsg) (Model, tea.Cmd) {
	s := m.setup
	if s == nil || msg.seq != s.seq {
		return m, nil // stale: the user moved on
	}
	s.loading = false
	if msg.err != nil {
		s.modelsErr = errText(msg.err)
		return m, nil
	}
	s.models = msg.models
	if len(s.models) == 0 {
		s.modelsErr = "the provider listed no tool-capable models"
	} else {
		s.model.Placeholder = "type to filter · or enter any model id"
	}
	if !s.filtering {
		s.pick = max(0, s.indexOf(strings.TrimSpace(s.model.Value())))
	}
	return m, nil
}

// matches is the catalog filtered by what the user typed (case-insensitive
// substring), with an exact match first.
func (s *setupState) matches() []string {
	q := strings.ToLower(strings.TrimSpace(s.model.Value()))
	if !s.filtering || q == "" {
		return s.models
	}
	var exact, rest []string
	for _, id := range s.models {
		switch l := strings.ToLower(id); {
		case l == q:
			exact = append(exact, id)
		case strings.Contains(l, q):
			rest = append(rest, id)
		}
	}
	return append(exact, rest...)
}

func (s *setupState) highlighted() string {
	ms := s.matches()
	if len(ms) == 0 {
		return ""
	}
	return ms[min(s.pick, len(ms)-1)]
}

func (s *setupState) indexOf(id string) int {
	for i, x := range s.models {
		if x == id {
			return i
		}
	}
	return -1
}

func (m *Model) connect(remember bool) tea.Cmd {
	s := m.setup
	creds := s.creds()
	creds.Remember = remember
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
	m.baseURL = msg.creds.BaseURL
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
		visible := max(3, min(len(s.opts.Providers), m.height-14))
		start := max(0, min(s.idx-visible/2, len(s.opts.Providers)-visible))
		for i := start; i < start+visible; i++ {
			p := s.opts.Providers[i]
			num := "  "
			if i < 9 {
				num = fmt.Sprintf("%d ", i+1)
			}
			line := fmt.Sprintf("%s %s", num, padRight(p.Label, 26))
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
		if visible < len(s.opts.Providers) {
			parts = append(parts, stDim.Render(fmt.Sprintf("  %d/%d", s.idx+1, len(s.opts.Providers))))
		}
		hint = "↑↓ choose  ·  ↵ next"
		if s.returnTo != phaseSetup {
			hint += "  ·  esc cancel"
		}
	case stepURL:
		parts = append(parts, stMuted.Render(c.Label+" base URL"), m.setupBox(s.url.View(), w),
			wrap(stDim, "the part before /chat/completions · a key is only ever sent over HTTPS or to localhost"))
		hint = "↵ next  ·  esc back"
	case stepKey:
		parts = append(parts, stMuted.Render(c.Label+" API key"), m.setupBox(s.key.View(), w))
		note := "input is masked · nothing is written until you choose to save"
		parts = append(parts, wrap(stDim, note))
		hint = "↵ next  ·  esc back"
	case stepModel:
		parts = append(parts, stMuted.Render(c.Label+" model"), m.setupBox(s.model.View(), w))
		parts = append(parts, m.modelList(w)...)
		hint = "↵ next  ·  esc back"
		if len(s.models) > 0 {
			hint = "type to filter  ·  ↑↓ pick  ·  tab fill  ·  ↵ next  ·  esc back"
		}
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

// modelList renders the catalog under the model input: a scrolling window of
// matches, or a loading / fallback line when there is no list.
func (m Model) modelList(w int) []string {
	s := m.setup
	c := s.choice()
	switch {
	case s.loading:
		return []string{m.spin.View() + " " + stMuted.Render("loading "+c.Label+" models…")}
	case s.modelsErr != "":
		out := []string{lipgloss.NewStyle().Foreground(colYellow).Render(ansi.Wrap("! no model list: "+s.modelsErr, w, ""))}
		if c.ModelHint != "" {
			out = append(out, stDim.Render(ansi.Wrap("type the id · "+c.ModelHint, w, "")))
		}
		return out
	case len(s.models) == 0:
		if c.ModelHint != "" {
			return []string{stDim.Render(ansi.Wrap(c.ModelHint, w, ""))}
		}
		return nil
	}
	ms := s.matches()
	if len(ms) == 0 {
		return []string{stDim.Render("  no listed model matches · ↵ uses what you typed")}
	}
	visible := max(2, min(8, m.height-17, len(ms)))
	pick := min(s.pick, len(ms)-1)
	start := max(0, min(pick-visible/2, len(ms)-visible))
	sel := lipgloss.NewStyle().Background(colSelected).Foreground(colLogo).Bold(true).Width(w)
	rows := []string{}
	for i := start; i < min(len(ms), start+visible); i++ {
		line := ansi.Truncate(ms[i], w-2, "…")
		if i == pick {
			rows = append(rows, sel.Render("› "+line))
		} else {
			rows = append(rows, stText.Render("  "+line))
		}
	}
	rows = append(rows, stDim.Render(fmt.Sprintf("  %d/%d · %d listed", pick+1, len(ms), len(s.models))))
	return []string{lipgloss.NewStyle().Width(w).Render(strings.Join(rows, "\n"))}
}

func (m Model) setupCrumbs() string {
	s := m.setup
	type crumb struct {
		name string
		step setupStep
	}
	crumbs := []crumb{{"provider", stepProvider}}
	if s.choice().NeedsURL {
		crumbs = append(crumbs, crumb{"url", stepURL})
	}
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
