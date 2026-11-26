package tui

import (
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"rogue/internal/engine"
)

const maxPickRows = 8

// pickerModelsMsg carries the provider catalog into an open /model picker.
type pickerModelsMsg struct {
	seq    int
	models []string
	err    error
}

// modelSwitchedMsg is the result of rebuilding the engine for a model that the
// current engine was not configured with.
type modelSwitchedMsg struct {
	eng   engine.Engine
	err   error
	creds Credentials
}

// openPicker shows the configured models at once and, when the provider is
// known, loads its full catalog in the background.
func (m *Model) openPicker() tea.Cmd {
	m.picker, m.pickFilter, m.pickErr = true, "", ""
	m.pickList = nil
	if m.eng != nil {
		m.pickList = m.eng.Models()
	}
	m.pickIdx = max(0, slices.Index(m.pickList, m.model))
	if m.setupCfg == nil || m.setupCfg.ListModels == nil || m.creds.Provider == "" {
		m.pickLoading = false
		return nil
	}
	m.pickSeq++
	m.pickLoading = true
	seq, list, creds := m.pickSeq, m.setupCfg.ListModels, m.creds
	creds.Model = ""
	return tea.Batch(m.spin.Tick, func() tea.Msg {
		models, err := list(creds)
		return pickerModelsMsg{seq: seq, models: models, err: err}
	})
}

func (m Model) onPickerModels(msg pickerModelsMsg) (Model, tea.Cmd) {
	if !m.picker || msg.seq != m.pickSeq {
		return m, nil // picker closed or reopened since
	}
	m.pickLoading = false
	if msg.err != nil {
		m.pickErr = errText(msg.err)
		return m, nil
	}
	current := m.pickHighlighted()
	for _, id := range msg.models { // configured models stay first
		if !slices.Contains(m.pickList, id) {
			m.pickList = append(m.pickList, id)
		}
	}
	if i := slices.Index(m.pickMatches(), current); i >= 0 {
		m.pickIdx = i
	}
	return m, nil
}

// pickMatches filters the list by what was typed (case-insensitive substring).
func (m Model) pickMatches() []string {
	q := strings.ToLower(strings.TrimSpace(m.pickFilter))
	if q == "" {
		return m.pickList
	}
	var out []string
	for _, id := range m.pickList {
		if strings.Contains(strings.ToLower(id), q) {
			out = append(out, id)
		}
	}
	return out
}

func (m Model) pickHighlighted() string {
	ms := m.pickMatches()
	if len(ms) == 0 {
		return ""
	}
	return ms[min(m.pickIdx, len(ms)-1)]
}

func (m Model) onPickerKey(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	switch k := msg.String(); k {
	case "esc":
		m.picker = false
	case "up":
		m.pickIdx = max(0, m.pickIdx-1)
	case "down":
		m.pickIdx = min(max(0, len(m.pickMatches())-1), m.pickIdx+1)
	case "backspace":
		if r := []rune(m.pickFilter); len(r) > 0 {
			m.pickFilter, m.pickIdx = string(r[:len(r)-1]), 0
		}
	case "enter":
		id := m.pickHighlighted()
		if id == "" {
			id = strings.TrimSpace(m.pickFilter) // not listed: use the typed id
		}
		if id == "" {
			return m, nil
		}
		return m.selectModel(id)
	default:
		if msg.Text != "" && !strings.ContainsAny(msg.Text, "\n\r\t") {
			m.pickFilter += msg.Text
			m.pickIdx = 0
		}
	}
	return m, nil
}

// selectModel switches instantly to a configured model; any other model needs
// a new engine, built through the same validated Connect path as setup.
func (m Model) selectModel(id string) (Model, tea.Cmd) {
	if m.eng != nil && slices.Contains(m.eng.Models(), id) {
		m.model, m.picker = id, false
		m.notice("model → " + id)
		return m, nil
	}
	if m.setupCfg == nil || m.setupCfg.Connect == nil || m.creds.Provider == "" {
		m.flash = id + " is not configured · add it to ROGUE_MODELS or use /provider"
		return m, nil
	}
	if m.running {
		m.flash = "a turn is running · esc to interrupt, then switch"
		return m, nil
	}
	m.picker, m.switching = false, true
	m.notice("switching to " + id + "…")
	creds, connect := m.creds, m.setupCfg.Connect
	creds.Model = id
	return m, tea.Batch(m.spin.Tick, func() tea.Msg {
		eng, err := connect(creds)
		return modelSwitchedMsg{eng: eng, err: err, creds: creds}
	})
}

func (m Model) onModelSwitched(msg modelSwitchedMsg) (Model, tea.Cmd) {
	m.switching = false
	if msg.eng == nil {
		text := "could not switch to " + msg.creds.Model + ": " + errText(msg.err)
		if m.phase == phaseLanding {
			m.flash = text // the landing screen has no transcript
		} else {
			m.push(entry{kind: entError, text: text})
		}
		return m, nil
	}
	m.eng, m.creds = msg.eng, msg.creds
	m.model = msg.creds.Model
	if ms := m.eng.Models(); len(ms) > 0 && !slices.Contains(ms, m.model) {
		m.model = ms[0]
	}
	text := "model → " + m.model
	switch {
	case msg.err != nil: // switched, but saving failed
		text += " · " + errText(msg.err)
	case msg.creds.Remember:
		text += " · saved as the default model"
	}
	m.notice(text)
	return m, nil
}

// pickerRows renders the /model picker above the input.
func (m Model) pickerRows(ww int) string {
	selected := lipgloss.NewStyle().Background(colSelected).Foreground(colLogo).Bold(true).Width(ww)
	rows := []string{stMuted.Render(ansi.Truncate("choose a model  ·  type to filter  ·  ↑↓  ·  ↵ select  ·  esc cancel", ww, "…"))}
	if m.pickFilter != "" {
		rows = append(rows, ansi.Truncate(stPrompt.Render("  / ")+stText.Render(m.pickFilter)+stPrompt.Render("▍"), ww, "…"))
	}
	ms := m.pickMatches()
	if len(ms) == 0 && m.pickFilter != "" {
		rows = append(rows, stDim.Render(ansi.Truncate("  not listed · ↵ tries \""+strings.TrimSpace(m.pickFilter)+"\"", ww, "…")))
	}
	pick := min(m.pickIdx, max(0, len(ms)-1))
	start := max(0, min(pick-maxPickRows/2, len(ms)-maxPickRows))
	for i := start; i < min(len(ms), start+maxPickRows); i++ {
		cur := "  "
		if ms[i] == m.model {
			cur = "● "
		}
		line := ansi.Truncate("  "+cur+ms[i], ww-1, "…")
		if i == pick {
			rows = append(rows, selected.Render("›"+line[1:]))
		} else {
			rows = append(rows, stText.Render(line))
		}
	}
	switch {
	case m.pickLoading:
		rows = append(rows, "  "+m.spin.View()+" "+stMuted.Render("loading the provider's models…"))
	case m.pickErr != "":
		rows = append(rows, fg(colYellow).Render(ansi.Truncate("  ! catalog unavailable: "+m.pickErr, ww, "…")))
	case len(ms) > maxPickRows || m.pickFilter != "":
		rows = append(rows, stDim.Render(fmt.Sprintf("  %d/%d · %d models", min(pick+1, len(ms)), len(ms), len(m.pickList))))
	}
	return strings.Join(rows, "\n")
}

// errorHint suggests the next step for provider errors a user can fix here.
func errorHint(text string) string {
	switch {
	case strings.Contains(text, "HTTP 429"):
		return "rate limit or quota exceeded for this model · /model to pick another, /provider to change provider"
	case strings.Contains(text, "HTTP 401"), strings.Contains(text, "HTTP 403"):
		return "the provider rejected the key · /provider to enter a new one"
	case strings.Contains(text, "HTTP 404"):
		return "model not found · /model to pick one from the catalog"
	}
	return ""
}
