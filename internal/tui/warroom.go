package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"rogue/internal/arsenal"
	"rogue/internal/bench"
	"rogue/internal/domain"
	"rogue/internal/engine"
)

// WarRoomServices keeps I/O at the application boundary. Each operation receives
// the current engine, including after a provider or model change.
type WarRoomServices struct {
	Catalog            func() []arsenal.Capability
	QuickRun           func(context.Context, engine.Engine, string, json.RawMessage, domain.Archetype, engine.Mode) (engine.Report, error)
	Export             func(engine.Engine, string, string, string) (string, error)
	ToolDetails        func(engine.Engine, string, engine.ToolCall) (string, error)
	Configure          func(engine.Engine, string, string, string) (engine.Engine, error)
	Benchmark          func(context.Context, engine.Engine, string, string, func(bench.SuiteResult)) (bench.SuiteResult, error)
	Lifecycle          func(string, engine.Event) error
	TokenLimit         int
	CostLimit          float64
	Profile, RoE, Team string
}

type warRoomState struct {
	tab                   int
	rows                  [6]int
	snapshot              engine.WarRoomSnapshot
	haveSnapshot, loading bool
	seq                   int
	catalog               []arsenal.Capability
	err                   string
	filter, severity      string
	filtering, composing  bool
	collapsed             map[string]bool
	modal                 string
	modalTitle            string
	pager                 viewport.Model
	pagerText             string
	form                  textarea.Model
	choice                int
	busy                  bool
	controlPending        bool
	jobCancel             context.CancelFunc
	jobID                 int
	benchmarks            map[string]bench.SuiteResult
	benchName             string
	benchUpdates          chan warResultMsg
	profile, roe, team    string
	approvals             []approvalMsg
	approvalCh            chan approvalMsg
	approvalDone          <-chan struct{}
	approvalOffset        int
}

type warTickMsg struct{}
type warSnapshotMsg struct {
	seq      int
	snapshot engine.WarRoomSnapshot
	found    bool
	catalog  []arsenal.Capability
}
type warResultMsg struct {
	id         int
	kind, text string
	err        error
	eng        engine.Engine
	suite      bench.SuiteResult
	partial    bool
}
type approvalMsg struct {
	ch      <-chan engine.Event
	request engine.ApprovalRequest
	reply   chan engine.ApprovalDecision
	done    <-chan struct{}
}

func waitApproval(ch <-chan approvalMsg, events <-chan engine.Event, done <-chan struct{}) tea.Cmd {
	return func() tea.Msg {
		select {
		case req := <-ch:
			req.ch = events
			return req
		case <-done:
			return nil
		}
	}
}

func (m Model) services() *WarRoomServices {
	if m.setupCfg == nil {
		return nil
	}
	return m.setupCfg.WarRoom
}

// The observer runs in event order outside Update. Cancellation and unexpected
// EOF both produce exactly one mission-abort hook, including /new and /quit.
func runTurn(ctx context.Context, eng engine.Engine, request engine.Request, observe func(string, engine.Event) error) <-chan engine.Event {
	if observe == nil {
		return eng.Run(ctx, request)
	}
	out := make(chan engine.Event, 64)
	go func() {
		defer close(out)
		notify := func(kind string, ev engine.Event) {
			if err := observe(kind, ev); err != nil {
				select {
				case out <- engine.Event{Kind: engine.KindNotice, Text: "plugin hook: " + err.Error()}:
				case <-ctx.Done():
				}
			}
		}
		notify("start", engine.Event{})
		finished := false
		defer func() {
			if !finished {
				err := ctx.Err()
				if err == nil {
					err = errors.New("engine ended without a terminal event")
				}
				notify("abort", engine.Event{Err: err})
			}
		}()
		events := eng.Run(ctx, request)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				switch ev.Kind {
				case engine.KindDone:
					notify("complete", ev)
					finished = true
				case engine.KindError:
					notify("abort", ev)
					finished = true
				default:
					notify("event", ev)
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
				if finished {
					return
				}
			}
		}
	}()
	return out
}

func (m Model) toggleWarRoom() (Model, tea.Cmd) {
	if m.phase == phaseWarRoom {
		m.phase = phaseSession
		m.war.composing = false
		m.input.Focus()
		return m, nil
	}
	m.phase = phaseWarRoom
	m.war.composing = false
	m.input.Blur()
	if m.war.collapsed == nil {
		m.war.collapsed = map[string]bool{}
	}
	if m.war.benchmarks == nil {
		m.war.benchmarks = map[string]bench.SuiteResult{}
	}
	if s := m.services(); s != nil && m.war.profile == "" {
		m.war.profile, m.war.roe, m.war.team = s.Profile, s.RoE, s.Team
	}
	return m, m.pollWarRoom()
}

func (m *Model) pruneApprovals() {
	kept := m.war.approvals[:0]
	for _, req := range m.war.approvals {
		select {
		case <-req.done:
		default:
			kept = append(kept, req)
		}
	}
	m.war.approvals = kept
}

func (m *Model) resetWarSnapshot() {
	m.war.seq++
	m.war.loading = false
	m.war.haveSnapshot = false
	m.war.snapshot = engine.WarRoomSnapshot{}
}

// Snapshot collection and availability probes can lock or touch the filesystem;
// neither runs in Update or View. Only one poll is outstanding at a time.
func (m *Model) pollWarRoom() tea.Cmd {
	if m.war.loading {
		return nil
	}
	m.war.loading = true
	m.war.seq++
	seq, eng, svc := m.war.seq, m.eng, m.services()
	return func() tea.Msg {
		msg := warSnapshotMsg{seq: seq}
		if insp, ok := eng.(engine.Inspector); ok {
			msg.snapshot, msg.found = insp.LiveSnapshot()
		}
		if svc != nil && svc.Catalog != nil {
			msg.catalog = svc.Catalog()
		}
		return msg
	}
}

func (m Model) onWarSnapshot(msg warSnapshotMsg) (Model, tea.Cmd) {
	if msg.seq != m.war.seq {
		return m, nil
	}
	m.war.loading = false
	if msg.found {
		m.war.snapshot, m.war.haveSnapshot = msg.snapshot, true
	}
	m.war.catalog = msg.catalog
	if m.phase != phaseWarRoom {
		return m, nil
	}
	return m, tea.Tick(750*time.Millisecond, func(time.Time) tea.Msg { return warTickMsg{} })
}

func (m Model) onWarResult(msg warResultMsg) (Model, tea.Cmd) {
	if msg.kind == "control" {
		m.war.controlPending = false
		if msg.err != nil {
			m.war.err = msg.err.Error()
		} else {
			m.war.err = ""
			m.flash = msg.text
		}
		return m, nil
	}
	if msg.id != m.war.jobID {
		return m, nil
	}
	if msg.kind == "benchmark" {
		if msg.suite.Suite != "" {
			m.war.benchmarks[msg.suite.Suite] = msg.suite
		}
		if msg.partial {
			return m, waitBench(m.war.benchUpdates)
		}
	}
	m.war.busy = false
	if m.war.jobCancel != nil {
		m.war.jobCancel()
		m.war.jobCancel = nil
	}
	if msg.err != nil {
		m.war.err = msg.err.Error()
		return m, nil
	}
	m.war.err = ""
	if msg.eng != nil {
		m.eng = msg.eng
		m.resetWarSnapshot()
	}
	if msg.kind == "preset" {
		parts := strings.Split(msg.text, "|")
		if len(parts) == 3 {
			m.war.profile, m.war.roe, m.war.team = parts[0], parts[1], parts[2]
			if parts[1] == "strict" && m.mode == engine.ModeAuto {
				m.mode = engine.ModeDefault
			}
		}
		msg.text = "presets updated · next mission"
	}
	switch msg.kind {
	case "details", "quick":
		m.openWarPager(msg.text)
	default:
		m.flash = msg.text
	}
	if msg.eng != nil && m.phase == phaseWarRoom {
		return m, m.pollWarRoom()
	}
	return m, nil
}

func waitBench(ch <-chan warResultMsg) tea.Cmd { return func() tea.Msg { return <-ch } }

func (m *Model) openWarPager(text string) {
	m.war.modal = "pager"
	m.war.pager = viewport.New()
	m.war.pager.SetWidth(max(1, min(100, m.width-8)))
	m.war.pager.SetHeight(max(1, m.height-8))
	m.war.pagerText = safeText(text)
	m.war.pager.SetContent(ansi.Wrap(m.war.pagerText, m.war.pager.Width(), ""))
}

func (m *Model) openWarForm(kind, title, initial string) {
	m.war.modal, m.war.modalTitle = kind, title
	f := textarea.New()
	f.SetStyles(inputStyles())
	f.CharLimit = 0
	f.KeyMap.InsertNewline = key.NewBinding(key.WithKeys("shift+enter", "alt+enter", "ctrl+j"))
	f.ShowLineNumbers = false
	f.SetWidth(max(1, min(90, m.width-10)))
	f.SetHeight(max(1, min(8, m.height-12)))
	f.SetValue(initial)
	f.Focus()
	m.war.form = f
}

func (m Model) onWarPaste(msg tea.PasteMsg) (Model, tea.Cmd) {
	if len(m.war.approvals) > 0 {
		return m, nil
	}
	var cmd tea.Cmd
	if m.war.modal != "" && m.war.modal != "pager" && m.war.modal != "export" {
		m.war.form, cmd = m.war.form.Update(msg)
	} else if m.war.filtering {
		m.war.filter += strings.Join(strings.Fields(msg.Content), " ")
	} else if m.war.composing {
		m.input, cmd = m.input.Update(msg)
	}
	return m, cmd
}

func (m Model) onWarMouse(msg tea.MouseWheelMsg) (Model, tea.Cmd) {
	if len(m.war.approvals) > 0 {
		if msg.Button == tea.MouseWheelUp {
			m.war.approvalOffset = max(0, m.war.approvalOffset-3)
		} else {
			m.war.approvalOffset += 3
		}
		return m, nil
	}
	if m.war.modal == "pager" {
		var cmd tea.Cmd
		m.war.pager, cmd = m.war.pager.Update(msg)
		return m, cmd
	}
	if msg.Button == tea.MouseWheelUp {
		m.war.rows[m.war.tab] = max(0, m.war.rows[m.war.tab]-3)
	} else {
		m.war.rows[m.war.tab] = min(max(0, m.warRowCount()-1), m.war.rows[m.war.tab]+3)
	}
	return m, nil
}

func (m Model) onWarKey(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	k := msg.String()
	if m.war.modal != "" {
		return m.onWarModalKey(msg)
	}
	if m.war.composing {
		if k == "esc" {
			m.war.composing = false
			m.input.Blur()
			return m, nil
		}
		if k == "enter" {
			next, cmd := m.submit()
			if next.input.Value() == "" {
				next.war.composing = false
				next.input.Blur()
			}
			return next, cmd
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	if m.war.filtering {
		switch k {
		case "enter", "esc":
			m.war.filtering = false
		case "backspace":
			rs := []rune(m.war.filter)
			if len(rs) > 0 {
				m.war.filter = string(rs[:len(rs)-1])
			}
		default:
			if msg.Text != "" {
				m.war.filter += msg.Text
			}
		}
		m.war.rows[m.war.tab] = 0
		return m, nil
	}
	switch k {
	case "esc":
		return m.toggleWarRoom()
	case "1", "2", "3", "4", "5", "6":
		m.war.tab = int(k[0] - '1')
		return m, nil
	case "tab":
		m.war.tab = (m.war.tab + 1) % 6
		return m, nil
	case "shift+tab":
		m.war.tab = (m.war.tab + 5) % 6
		return m, nil
	case "i":
		if m.war.tab == 3 {
			m.war.severity = "info"
			m.war.rows[3] = 0
			return m, nil
		}
		m.war.composing = true
		return m, m.input.Focus()
	case ":":
		m.war.composing = true
		return m, m.input.Focus()
	case "j", "down":
		m.war.rows[m.war.tab] = min(max(0, m.warRowCount()-1), m.war.rows[m.war.tab]+1)
	case "k", "up":
		m.war.rows[m.war.tab] = max(0, m.war.rows[m.war.tab]-1)
	case "pgdown":
		m.war.rows[m.war.tab] = min(max(0, m.warRowCount()-1), m.war.rows[m.war.tab]+max(1, m.height-12))
	case "pgup":
		m.war.rows[m.war.tab] = max(0, m.war.rows[m.war.tab]-max(1, m.height-12))
	case "g":
		m.war.rows[m.war.tab] = 0
	case "G":
		m.war.rows[m.war.tab] = max(0, m.warRowCount()-1)
	case "/":
		if m.war.tab == 4 {
			m.war.filtering = true
		}
	case "c", "h", "m", "l", "a":
		if m.war.tab == 3 {
			vals := map[string]string{"c": "critical", "h": "high", "m": "medium", "l": "low", "a": ""}
			m.war.severity = vals[k]
			m.war.rows[3] = 0
		}
	case "e":
		if m.war.tab == 3 {
			m.war.modal = "export"
			m.war.choice = 0
		}
	case "enter":
		return m.activateWarRow()
	case "p", "r", "t":
		if m.war.tab == 5 {
			return m.cyclePreset(k)
		}
	case "b":
		if m.war.tab == 5 && !m.running && !m.war.busy {
			name := benchmarkNames[min(m.war.rows[5], len(benchmarkNames)-1)]
			target, title := "http://127.0.0.1:3000", "Benchmark target URL"
			if name == "local-ctf" {
				target, title = "ctf/challenges", "Local CTF challenge directory"
			}
			if name == "cybench" || name == "nyu-ctf" {
				target, title = "run", "Load public suite metadata · enter run to start"
			}
			m.openWarForm("benchmark", name+" · "+title, target)
		}
	case "d":
		if m.war.tab == 5 {
			m.openWarPager(pretty(m.war.snapshot.OPSEC))
		}
	case " ", "space":
		return m.pauseWarMission()
	case "x":
		if m.war.busy && m.war.jobCancel != nil {
			m.war.jobCancel()
			m.flash = "cancelling operation…"
		}
	}
	return m, nil
}

func (m Model) pauseWarMission() (Model, tea.Cmd) {
	if m.war.controlPending {
		return m, nil
	}
	ctrl, ok := m.eng.(interface {
		PauseMission(string) error
		ResumeMission(string) error
	})
	if !ok || !m.war.haveSnapshot {
		m.war.err = "no controllable mission"
		return m, nil
	}
	id, status := m.war.snapshot.MissionID, m.war.snapshot.Status
	m.war.controlPending = true
	return m, func() tea.Msg {
		var err error
		if status == "paused" {
			err = ctrl.ResumeMission(id)
		} else {
			err = ctrl.PauseMission(id)
		}
		return warResultMsg{kind: "control", text: "mission control updated", err: err}
	}
}

func (m Model) onApprovalKey(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	decision := engine.ApprovalDeny
	switch msg.String() {
	case "down", "j":
		m.war.approvalOffset++
		return m, nil
	case "up", "k":
		m.war.approvalOffset = max(0, m.war.approvalOffset-1)
		return m, nil
	case "pgdown":
		m.war.approvalOffset += max(1, m.height-10)
		return m, nil
	case "pgup":
		m.war.approvalOffset = max(0, m.war.approvalOffset-max(1, m.height-10))
		return m, nil
	case "y":
		decision = engine.ApprovalOnce
	case "a":
		decision = engine.ApprovalMission
	case "n":
	default:
		return m, nil
	}
	req := m.war.approvals[0]
	req.reply <- decision
	m.war.approvals = m.war.approvals[1:]
	m.war.approvalOffset = 0
	if len(m.war.approvals) == 0 && m.phase != phaseWarRoom {
		m.input.Focus()
	}
	return m, nil
}

var exportFormats = []string{"json", "sarif", "html", "markdown", "pdf"}
var benchmarkNames = []string{"cybench", "nyu-ctf", "xbow", "juice-shop", "local-ctf"}

func (m Model) onWarModalKey(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	k := msg.String()
	if k == "esc" {
		m.war.modal = ""
		return m, nil
	}
	if m.war.modal == "pager" {
		var cmd tea.Cmd
		m.war.pager, cmd = m.war.pager.Update(msg)
		return m, cmd
	}
	if m.war.modal == "export" {
		switch k {
		case "j", "down":
			m.war.choice = min(len(exportFormats)-1, m.war.choice+1)
		case "k", "up":
			m.war.choice = max(0, m.war.choice-1)
		case "enter":
			f := exportFormats[m.war.choice]
			ext := f
			if ext == "markdown" {
				ext = "md"
			}
			m.openWarForm("export-path", "Export "+strings.ToUpper(f)+" · destination", "rogue-"+m.war.snapshot.MissionID+"."+ext)
		}
		return m, nil
	}
	if k != "enter" {
		var cmd tea.Cmd
		m.war.form, cmd = m.war.form.Update(msg)
		return m, cmd
	}
	if m.war.busy {
		m.war.err = "wait for the current operation"
		return m, nil
	}
	s := m.services()
	if s == nil {
		m.war.err = "War Room actions are unavailable"
		return m, nil
	}
	value := strings.TrimSpace(m.war.form.Value())
	eng := m.eng
	mission := m.war.snapshot.MissionID
	var action func(int, context.Context) tea.Cmd
	switch m.war.modal {
	case "export-path":
		if s.Export == nil || mission == "" || value == "" {
			m.war.err = "mission and destination required"
			return m, nil
		}
		format := exportFormats[m.war.choice]
		action = func(id int, _ context.Context) tea.Cmd {
			return func() tea.Msg {
				path, err := s.Export(eng, mission, format, value)
				return warResultMsg{id: id, kind: "export", text: "exported · " + path, err: err}
			}
		}
	case "quick":
		if s.QuickRun == nil || m.running {
			m.war.err = "finish the active turn before a quick run"
			return m, nil
		}
		var body struct {
			Operator  domain.Archetype `json:"operator"`
			Arguments json.RawMessage  `json:"arguments"`
		}
		if json.Unmarshal([]byte(value), &body) != nil || body.Operator == "" || len(body.Arguments) == 0 || !jsonObject(body.Arguments) {
			m.war.err = "enter an operator and an arguments JSON object"
			return m, nil
		}
		tools := m.filteredCatalog()
		if len(tools) == 0 {
			return m, nil
		}
		tool := tools[min(m.war.rows[4], len(tools)-1)].Name
		mode := m.mode
		action = func(id int, ctx context.Context) tea.Cmd {
			return func() tea.Msg {
				report, err := s.QuickRun(ctx, eng, tool, body.Arguments, body.Operator, mode)
				data, _ := json.MarshalIndent(report, "", "  ")
				return warResultMsg{id: id, kind: "quick", text: string(data), err: err}
			}
		}
	case "benchmark":
		if s.Benchmark == nil || m.running {
			m.war.err = "benchmark unavailable while a turn is active"
			return m, nil
		}
		name := benchmarkNames[min(m.war.rows[5], len(benchmarkNames)-1)]
		if value == "" {
			m.war.err = "target or directory required"
			return m, nil
		}
		m.war.benchName = name
		m.war.benchUpdates = make(chan warResultMsg, 8)
		updates := m.war.benchUpdates
		action = func(id int, ctx context.Context) tea.Cmd {
			return func() tea.Msg {
				go func() {
					result, err := s.Benchmark(ctx, eng, name, value, func(part bench.SuiteResult) {
						select {
						case updates <- warResultMsg{id: id, kind: "benchmark", suite: part, partial: true}:
						case <-ctx.Done():
						}
					})
					updates <- warResultMsg{id: id, kind: "benchmark", suite: result, err: err, text: "benchmark complete · " + name}
				}()
				return <-updates
			}
		}
	}
	if action == nil {
		return m, nil
	}
	m.war.modal = ""
	m.war.err = ""
	m.war.busy = true
	m.war.jobID++
	ctx, cancel := context.WithCancel(context.Background())
	m.war.jobCancel = cancel
	return m, action(m.war.jobID, ctx)
}

func jsonObject(data []byte) bool {
	var obj map[string]json.RawMessage
	return json.Unmarshal(data, &obj) == nil && obj != nil
}

func (m Model) cyclePreset(key string) (Model, tea.Cmd) {
	if m.running || m.war.busy {
		m.war.err = "presets apply between missions · finish the active operation"
		return m, nil
	}
	s := m.services()
	if s == nil || s.Configure == nil {
		m.war.err = "preset configuration unavailable"
		return m, nil
	}
	next := func(current string, values []string) string {
		for i, v := range values {
			if current == v {
				return values[(i+1)%len(values)]
			}
		}
		return values[0]
	}
	p, r, t := m.war.profile, m.war.roe, m.war.team
	switch key {
	case "p":
		p = next(p, []string{"silent", "covert", "loud"})
	case "r":
		r = next(r, []string{"strict", "default"})
	case "t":
		t = next(t, []string{"balanced", "stealth", "breach"})
	}
	eng := m.eng
	m.war.jobID++
	id := m.war.jobID
	m.war.busy = true
	// Commit the selected labels only when rebuilding the engine succeeds.
	return m, func() tea.Msg {
		backend, err := s.Configure(eng, p, r, t)
		return warResultMsg{id: id, kind: "preset", eng: backend, text: p + "|" + r + "|" + t, err: err}
	}
}

func (m Model) warEngineConfig() func(engine.Engine) (engine.Engine, error) {
	s := m.services()
	p, r, t := m.war.profile, m.war.roe, m.war.team
	if s == nil || s.Configure == nil || p == "" || r == "" || t == "" {
		return func(eng engine.Engine) (engine.Engine, error) { return eng, nil }
	}
	return func(eng engine.Engine) (engine.Engine, error) { return s.Configure(eng, p, r, t) }
}

// Strip terminal controls from untrusted tool/model text before drawing it.
func safeText(s string) string {
	s = ansi.Strip(s)
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
}

func pretty(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(data)
}

func (m Model) warInputWidth() int {
	if m.width >= 120 {
		return max(1, (m.width-5)*58/100)
	}
	return max(1, m.width-4)
}
