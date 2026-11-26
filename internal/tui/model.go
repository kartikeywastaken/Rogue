// Package tui is Rogue's terminal interface: a centered landing screen that
// flows into a streaming session view. It talks to the harness only through
// engine.Engine.
package tui

import (
	"context"
	"os"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"rogue/internal/engine"
)

type phase int

const (
	phaseLanding phase = iota
	phaseSession
	phaseSetup // provider / API key / model entry
	phaseWarRoom
)

type entryKind int

const (
	entUser entryKind = iota
	entAssistant
	entTool
	entNotice
	entError
)

type entry struct {
	kind    entryKind
	text    string
	at      time.Time
	tool    engine.ToolCall
	running bool
}

type Model struct {
	eng engine.Engine

	phase         phase
	width, height int

	input textarea.Model
	vp    viewport.Model
	spin  spinner.Model

	entries []entry

	// current turn
	running   bool
	cancel    context.CancelFunc
	events    <-chan engine.Event
	turnStart time.Time
	usage     engine.Usage
	total     engine.Usage

	model string
	mode  engine.Mode
	cwd   string

	palIdx      int  // highlighted slash command
	picker      bool // model picker open
	pickIdx     int
	pickFilter  string   // typed filter
	pickList    []string // configured models first, then the provider catalog
	pickLoading bool
	pickErr     string
	pickSeq     int    // identifies the latest catalog request
	switching   bool   // rebuilding the engine for a newly picked model
	flash       string // one-line inline error under the input

	history []string
	histIdx int

	jump bool // scroll to the tail on the next refresh

	wmIdx int // wordmark style on the landing screen (tab cycles)

	setupCfg *Setup      // nil when in-TUI provider setup is unavailable
	setup    *setupState // non-nil while the setup screen is open
	creds    Credentials // what the current engine was built from (key only if typed)
	provider string      // provider connected through setup, if any
	baseURL  string      // its base URL, when the provider needs one
	war      warRoomState
}

// eventMsg carries one engine event back onto the Elm loop. ch identifies the
// turn so events from an interrupted turn are dropped.
type eventMsg struct {
	ch <-chan engine.Event
	ev engine.Event
	ok bool
}

func waitFor(ch <-chan engine.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		return eventMsg{ch: ch, ev: ev, ok: ok}
	}
}

// New starts the TUI on an already configured engine.
func New(eng engine.Engine) Model { return NewWithSetup(eng, nil) }

// NewWithSetup starts the TUI with in-app provider setup available through
// /provider. When eng is nil (nothing configured yet) it opens on the setup
// screen instead of the landing screen.
func NewWithSetup(eng engine.Engine, setup *Setup) Model {
	ta := textarea.New()
	ta.ShowLineNumbers = false
	ta.CharLimit = 0
	ta.DynamicHeight = true
	ta.MinHeight = 1
	ta.MaxHeight = 8
	ta.SetPromptFunc(2, func(info textarea.PromptInfo) string {
		if info.LineNumber == 0 {
			return "› "
		}
		return "  "
	})
	ta.KeyMap.InsertNewline = key.NewBinding(key.WithKeys("shift+enter", "alt+enter", "ctrl+j"))
	ta.SetStyles(inputStyles())
	ta.Focus()

	vp := viewport.New()
	vp.KeyMap = viewport.KeyMap{} // keys go to the input; we drive scrolling ourselves
	vp.MouseWheelDelta = 3

	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(stYellow))

	cwd, _ := os.Getwd()
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(cwd, home) {
		cwd = "~" + strings.TrimPrefix(cwd, home)
	}

	model := ""
	if eng != nil {
		if ms := eng.Models(); len(ms) > 0 {
			model = ms[0]
		}
	}

	m := Model{
		eng:      eng,
		input:    ta,
		vp:       vp,
		spin:     sp,
		model:    model,
		cwd:      cwd,
		setupCfg: setup,
	}
	if setup != nil {
		m.creds = setup.Current
	}
	if eng == nil {
		m.openSetup()
	}
	return m
}

func inputStyles() textarea.Styles {
	s := textarea.DefaultDarkStyles()
	for _, st := range []*textarea.StyleState{&s.Focused, &s.Blurred} {
		st.Base = fg(colText)
		st.Text = fg(colText)
		st.CursorLine = fg(colText) // no fill: the ground shows through
		st.Placeholder = fg(colDim)
		st.Prompt = fg(colPrompt).Bold(true)
		st.EndOfBuffer = fg(colGround)
	}
	s.Cursor.Color = colPrompt
	s.Cursor.Blink = false
	return s
}

func (m Model) Init() tea.Cmd { return nil }

// Update wraps update so layout and transcript are always in sync with state.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, cmd := m.update(msg)
	m.pruneApprovals()
	// Decide whether to stick to the tail after the user's own scrolling but
	// before content or height change underneath them.
	follow := m.vp.AtBottom() || m.jump
	m.jump = false
	m.layout()
	m.refresh(follow)
	return m, cmd
}

func (m Model) update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.war.modal == "pager" {
			offset := m.war.pager.YOffset()
			m.openWarPager(m.war.pagerText)
			m.war.pager.SetYOffset(offset)
		}
		if m.war.modal == "quick" || m.war.modal == "benchmark" || m.war.modal == "export-path" {
			m.war.form.SetWidth(max(1, min(90, m.width-10)))
			m.war.form.SetHeight(max(1, min(8, m.height-12)))
		}
		return m, nil

	case eventMsg:
		return m.onEvent(msg)
	case warSnapshotMsg:
		return m.onWarSnapshot(msg)
	case warTickMsg:
		if m.phase == phaseWarRoom {
			return m, m.pollWarRoom()
		}
		return m, nil
	case warResultMsg:
		return m.onWarResult(msg)
	case approvalMsg:
		if msg.ch != m.events || !m.running {
			return m, nil
		}
		m.war.approvals = append(m.war.approvals, msg)
		m.input.Blur()
		return m, waitApproval(m.war.approvalCh, m.events, m.war.approvalDone)

	case connectedMsg:
		return m.onConnected(msg)

	case modelsMsg:
		return m.onModels(msg)

	case pickerModelsMsg:
		return m.onPickerModels(msg)

	case modelSwitchedMsg:
		return m.onModelSwitched(msg)

	case spinner.TickMsg:
		busy := m.running || m.switching || (m.picker && m.pickLoading) ||
			(m.setup != nil && (m.setup.step == stepConnecting || m.setup.loading))
		if !busy {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.MouseWheelMsg:
		if m.phase == phaseWarRoom {
			return m.onWarMouse(msg)
		}
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd

	case tea.PasteMsg:
		if m.phase == phaseWarRoom || len(m.war.approvals) > 0 {
			return m.onWarPaste(msg)
		}
		var cmd tea.Cmd
		if s := m.setup; s != nil {
			switch s.step {
			case stepURL:
				s.url, cmd = s.url.Update(msg)
			case stepKey:
				s.key, cmd = s.key.Update(msg)
			case stepModel:
				s.model, cmd = s.model.Update(msg)
			}
			return m, cmd
		}
		if m.picker {
			m.pickFilter += strings.Join(strings.Fields(msg.Content), "")
			m.pickIdx = 0
			return m, nil
		}
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m Model) onKey(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	k := msg.String()
	if k == "ctrl+c" {
		m.stopTurn()
		if m.war.jobCancel != nil {
			m.war.jobCancel()
		}
		return m, tea.Quit
	}
	m.flash = ""
	if len(m.war.approvals) > 0 {
		return m.onApprovalKey(msg)
	}

	if m.setup != nil {
		return m.onSetupKey(msg)
	}

	if m.picker {
		return m.onPickerKey(msg)
	}
	if k == "ctrl+w" {
		return m.toggleWarRoom()
	}
	if m.phase == phaseWarRoom {
		return m.onWarKey(msg)
	}

	if cmds := m.paletteItems(); cmds != nil {
		switch k {
		case "up":
			m.palIdx = max(0, m.palIdx-1)
			return m, nil
		case "down":
			m.palIdx = min(len(cmds)-1, m.palIdx+1)
			return m, nil
		case "tab":
			if len(cmds) > 0 {
				m.input.SetValue(cmds[m.palIdx].name + " ")
				m.input.CursorEnd()
			}
			return m, nil
		case "esc":
			m.input.Reset()
			return m, nil
		case "enter":
			if len(cmds) > 0 {
				m.input.Reset()
				return m.runCommand(cmds[m.palIdx].name)
			}
		}
	}

	switch k {
	case "esc":
		if m.running {
			m.stopTurn()
			m.push(entry{kind: entNotice, text: "interrupted"})
		}
		return m, nil
	case "tab":
		if m.phase == phaseLanding {
			m.wmIdx = (m.wmIdx + 1) % len(wordmarks)
			return m, nil
		}
	case "shift+tab":
		m.mode = m.mode.Next()
		m.notice("mode → " + m.mode.String())
		return m, nil
	case "enter":
		return m.submit()
	case "pgup":
		m.vp.PageUp()
		return m, nil
	case "pgdown":
		m.vp.PageDown()
		return m, nil
	case "up":
		if m.input.Line() == 0 && m.histIdx > 0 {
			m.histIdx--
			m.input.SetValue(m.history[m.histIdx])
			return m, nil
		}
	case "down":
		if m.input.Line() == m.input.LineCount()-1 && m.histIdx < len(m.history) {
			m.histIdx++
			if m.histIdx == len(m.history) {
				m.input.Reset()
			} else {
				m.input.SetValue(m.history[m.histIdx])
			}
			return m, nil
		}
	}

	prev := m.input.Value()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if m.input.Value() != prev {
		m.palIdx = 0
	}
	return m, cmd
}

func (m Model) submit() (Model, tea.Cmd) {
	text := strings.TrimSpace(m.input.Value())
	if text == "" {
		return m, nil
	}
	if strings.HasPrefix(text, "/") {
		m.input.Reset()
		return m.runCommand(text)
	}
	if m.running {
		m.flash = "a turn is running · esc to interrupt"
		return m, nil
	}
	if m.switching {
		m.flash = "switching model · one moment"
		return m, nil
	}

	if m.war.busy {
		m.flash = "a War Room operation is running · x to cancel"
		return m, nil
	}
	if m.eng == nil {
		m.flash = "connect a provider first · /provider"
		return m, nil
	}
	if m.war.roe == "strict" && m.mode == engine.ModeAuto {
		m.flash = "strict RoE requires default or plan mode"
		return m, nil
	}
	m.input.Reset()
	if n := len(m.history); n == 0 || m.history[n-1] != text {
		m.history = append(m.history, text)
	}
	m.histIdx = len(m.history)

	if m.phase != phaseWarRoom {
		m.phase = phaseSession
	}
	m.push(entry{kind: entUser, text: text})
	m.jump = true

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.war.approvalCh = make(chan approvalMsg, 8)
	m.war.approvalDone = ctx.Done()
	requests := m.war.approvalCh
	ctx = engine.WithApprovalHandler(ctx, func(ctx context.Context, req engine.ApprovalRequest) (engine.ApprovalDecision, error) {
		reply := make(chan engine.ApprovalDecision, 1)
		select {
		case requests <- approvalMsg{request: req, reply: reply, done: ctx.Done()}:
		case <-ctx.Done():
			return engine.ApprovalDeny, ctx.Err()
		}
		select {
		case decision := <-reply:
			return decision, nil
		case <-ctx.Done():
			return engine.ApprovalDeny, ctx.Err()
		}
	})
	var observer func(string, engine.Event) error
	if svc := m.services(); svc != nil {
		observer = svc.Lifecycle
	}
	m.events = runTurn(ctx, m.eng, engine.Request{Prompt: text, Model: m.model, Mode: m.mode}, observer)
	m.running = true
	m.turnStart = time.Now()
	m.usage = engine.Usage{}
	return m, tea.Batch(waitFor(m.events), waitApproval(requests, m.events, ctx.Done()), m.spin.Tick)
}

func (m Model) onEvent(msg eventMsg) (Model, tea.Cmd) {
	if msg.ch != m.events || !m.running {
		return m, nil // stale event from an interrupted turn
	}
	if !msg.ok {
		m.endTurn()
		return m, nil
	}

	ev := msg.ev
	switch ev.Kind {
	case engine.KindText:
		if n := len(m.entries); n > 0 && m.entries[n-1].kind == entAssistant {
			m.entries[n-1].text += ev.Text
		} else {
			m.push(entry{kind: entAssistant, text: strings.TrimLeft(ev.Text, " ")})
		}
	case engine.KindToolStart:
		m.push(entry{kind: entTool, tool: ev.Tool, running: true})
	case engine.KindToolEnd:
		for i := len(m.entries) - 1; i >= 0; i-- {
			if m.entries[i].kind == entTool && m.entries[i].tool.ID == ev.Tool.ID {
				m.entries[i].tool = ev.Tool
				m.entries[i].running = false
				break
			}
		}
	case engine.KindUsage:
		m.usage = ev.Usage
	case engine.KindNotice:
		m.push(entry{kind: entNotice, text: ev.Text})
	case engine.KindError:
		text := "engine error"
		if ev.Err != nil {
			text = ev.Err.Error()
		}
		m.push(entry{kind: entError, text: text})
		if hint := errorHint(text); hint != "" {
			m.push(entry{kind: entNotice, text: hint})
		}
		m.endTurn()
		return m, nil
	case engine.KindDone:
		m.endTurn()
		return m, nil
	}
	return m, waitFor(m.events)
}

// endTurn closes out a turn that finished on its own.
func (m *Model) endTurn() {
	m.total.Input += m.usage.Input
	m.total.Output += m.usage.Output
	m.usage = engine.Usage{}
	m.stopTurn()
}

// stopTurn cancels the engine and marks any still-running tools as stopped.
func (m *Model) stopTurn() {
	if m.cancel != nil {
		m.cancel()
	}
	m.cancel, m.events, m.running = nil, nil, false
	m.war.approvals = nil
	m.input.Focus()
	for i := range m.entries {
		if m.entries[i].kind == entTool && m.entries[i].running {
			m.entries[i].running = false
			m.entries[i].tool.Output = "stopped"
		}
	}
}

func (m *Model) push(e entry) { e.at = time.Now(); m.entries = append(m.entries, e) }

// notice records a status line in the transcript, or flashes it on the landing.
func (m *Model) notice(text string) {
	if m.phase == phaseLanding {
		m.flash = text
		return
	}
	m.push(entry{kind: entNotice, text: text})
}

// layout sizes the input and transcript to the current terminal.
func (m *Model) layout() {
	if m.width == 0 {
		return
	}
	ww := m.workWidth()
	if m.phase == phaseWarRoom {
		ww = m.warInputWidth()
	}
	m.input.SetWidth(max(1, ww-4)) // rounded border + 1 col padding each side
	if s := m.setup; s != nil {
		w := min(ww, 72) - 4 - 2 // box chrome, then the "› " prompt
		s.url.SetWidth(w)
		s.key.SetWidth(w)
		s.model.SetWidth(w)
	}
	if m.phase == phaseLanding {
		m.input.Placeholder = "Ask Rogue anything · / for commands"
	} else {
		m.input.Placeholder = "Message Rogue"
	}
	m.vp.SetWidth(ww)
	m.vp.SetHeight(max(1, m.height-m.chromeHeight()))
}

// refresh re-renders the transcript, following the tail if asked.
func (m *Model) refresh(follow bool) {
	if m.width == 0 || m.phase != phaseSession {
		return
	}
	m.vp.SetContent(m.renderTranscript(m.vp.Width()))
	if follow {
		m.vp.GotoBottom()
	}
}

func (m Model) workWidth() int {
	return max(20, min(100, m.width-4))
}
