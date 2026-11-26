package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const maxListRows = 6

func (m Model) View() tea.View {
	v := tea.NewView("")
	v.AltScreen = true
	v.BackgroundColor = colGround // the one ground; nothing else paints it
	v.ForegroundColor = colText
	v.WindowTitle = "rogue"
	if m.width == 0 || m.height == 0 {
		return v
	}
	var body string
	switch m.phase {
	case phaseSetup:
		body = m.viewSetup()
	case phaseLanding:
		body = m.viewLanding()
	default:
		v.MouseMode = tea.MouseModeCellMotion
		body = m.viewSession()
	}
	v.SetContent(clip(body, m.width, m.height))
	return v
}

// ── landing ──────────────────────────────────────────────────────────────────

func (m Model) viewLanding() string {
	parts := []string{}
	if m.height >= 24 {
		parts = append(parts, stPrompt.Render("◆"), "")
	}
	wm := renderWordmark(wordmarks[m.wmIdx].word, m.width, m.height)
	parts = append(parts, lipgloss.NewStyle().Width(lipgloss.Width(wm)).Render(wm))
	if m.height >= 18 {
		parts = append(parts, "", stMuted.Render("Security focused Harness"))
	}
	parts = append(parts, "", m.inputBox())
	if list := m.renderList(); list != "" {
		parts = append(parts, list)
	}
	if m.flash != "" {
		parts = append(parts, stRed.Render(m.flash))
	} else {
		hint := "tab next  ·  ↵ send  ·  / commands"
		if lipgloss.Width(hint) > m.width-2 {
			hint = "↵ send  ·  / cmds"
		}
		parts = append(parts, stDim.Render(hint))
	}
	stack := lipgloss.JoinVertical(lipgloss.Center, parts...)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, stack)
}

// ── session ──────────────────────────────────────────────────────────────────

func (m Model) viewSession() string {
	ww := m.workWidth()
	pad := strings.Repeat(" ", max(0, (m.width-ww)/2))
	indent := func(s string) string {
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = pad + lines[i]
		}
		return strings.Join(lines, "\n")
	}

	left := stLogo.Render("◆ ROGUE")
	right := stDim.Render(ansi.Truncate(m.cwd, max(0, ww-lipgloss.Width(left)-2), "…"))
	header := left + strings.Repeat(" ", max(1, ww-lipgloss.Width(left)-lipgloss.Width(right))) + right
	rule := stDim.Render(strings.Repeat("─", ww))

	rows := []string{
		indent(header),
		indent(rule),
		indent(fitLines(m.vp.View(), m.vp.Height())),
		"",
	}
	if list := m.renderList(); list != "" {
		rows = append(rows, indent(list))
	}
	if m.flash != "" {
		rows = append(rows, indent(stRed.Render(m.flash)))
	}
	rows = append(rows, indent(m.inputBox()))
	return strings.Join(rows, "\n")
}

// chromeHeight is everything in the session view that isn't the transcript.
func (m Model) chromeHeight() int {
	h := 2 + 1 + m.input.Height() + 2 // header+rule, gap, input box
	h += m.listHeight()
	if m.flash != "" {
		h++
	}
	return h
}

func (m Model) inputBox() string {
	border := colAccent
	if m.running {
		border = colBorderDim
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Render(m.input.View())
}

// ── palette / picker ─────────────────────────────────────────────────────────

func (m Model) listHeight() int {
	if s := m.renderList(); s != "" {
		return lipgloss.Height(s)
	}
	return 0
}

// renderList draws the slash palette or model picker as a block exactly one
// work-width wide, so centering never shifts individual rows.
func (m Model) renderList() string {
	s := m.listRows()
	if s == "" {
		return ""
	}
	return lipgloss.NewStyle().Width(m.workWidth()).Render(s)
}

func (m Model) listRows() string {
	ww := m.workWidth()
	selected := lipgloss.NewStyle().Background(colSelected).Foreground(colLogo).Bold(true).Width(ww)

	if m.picker {
		return m.pickerRows(ww)
	}

	items := m.paletteItems()
	if items == nil {
		return ""
	}
	if len(items) == 0 {
		return stDim.Render("  no matching commands")
	}
	start := max(0, min(m.palIdx-maxListRows+1, len(items)-maxListRows))
	end := min(len(items), start+maxListRows)
	rows := []string{}
	for i := start; i < end; i++ {
		c := items[i]
		if i == m.palIdx {
			rows = append(rows, selected.Render(ansi.Truncate("› "+padRight(c.name, 10)+c.desc, ww, "…")))
		} else {
			rows = append(rows, ansi.Truncate("  "+stText.Render(padRight(c.name, 10))+stMuted.Render(c.desc), ww, "…"))
		}
	}
	return strings.Join(rows, "\n")
}

// ── transcript ───────────────────────────────────────────────────────────────

func (m Model) renderTranscript(w int) string {
	if len(m.entries) == 0 {
		return stDim.Render("  nothing here yet")
	}
	var out []string
	for i, e := range m.entries {
		if i > 0 && !(e.kind == entNotice && m.entries[i-1].kind == entNotice) &&
			!(e.kind == entTool && m.entries[i-1].kind == entTool) {
			out = append(out, "")
		}
		last := i == len(m.entries)-1
		switch e.kind {
		case entUser:
			out = append(out, gutter(stPrompt.Bold(true).Render("› "), stBold, e.text, w)...)
		case entAssistant:
			lines := gutter(stLogo.Render("◆ "), stText, e.text, w)
			if last && m.running {
				lines[len(lines)-1] += stLogo.Render("▍")
			}
			out = append(out, lines...)
		case entTool:
			out = append(out, m.renderTool(e, w)...)
		case entNotice:
			out = append(out, gutter(stDim.Render("  · "), stMuted, e.text, w)...)
		case entError:
			out = append(out, gutter(stRed.Render("  ✗ "), stRed, e.text, w)...)
		}
	}
	if m.running && m.waiting() {
		out = append(out, "", "  "+m.spin.View()+" "+stMuted.Render("thinking"))
	}
	return strings.Join(out, "\n")
}

// waiting reports whether the turn is running with nothing visibly streaming.
func (m Model) waiting() bool {
	last := m.entries[len(m.entries)-1]
	switch last.kind {
	case entAssistant:
		return false
	case entTool:
		return !last.running
	}
	return true
}

func (m Model) renderTool(e entry, w int) []string {
	icon := stGreen.Render("✓")
	switch {
	case e.running:
		icon = m.spin.View()
	case !e.tool.OK:
		icon = stRed.Render("✗")
	}
	head := "  " + icon + " " + stCyan.Bold(true).Render(e.tool.Name)
	if e.tool.Input != "" {
		head += stMuted.Render(" " + e.tool.Input)
	}
	lines := []string{ansi.Truncate(head, w, "…")}
	switch {
	case e.running:
		lines = append(lines, stDim.Render("    └ running…"))
	case e.tool.Output != "":
		lines = append(lines, ansi.Truncate(stDim.Render("    └ "+e.tool.Output), w, "…"))
	}
	return lines
}

// gutter word-wraps text beside a 2–4 cell prefix, hanging the continuation.
func gutter(prefix string, style lipgloss.Style, text string, w int) []string {
	pw := lipgloss.Width(prefix)
	hang := strings.Repeat(" ", pw)
	wrapped := strings.Split(ansi.Wrap(text, max(1, w-pw), ""), "\n")
	for i, l := range wrapped {
		p := hang
		if i == 0 {
			p = prefix
		}
		wrapped[i] = p + style.Render(l)
	}
	return wrapped
}

// ── helpers ──────────────────────────────────────────────────────────────────

// fitLines pads or trims s to exactly n lines.
func fitLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	for len(lines) < n {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// clip guarantees the frame never exceeds the terminal, so nothing wraps or
// scrolls the alt screen.
func clip(s string, w, h int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			lines[i] = ansi.Truncate(l, w, "")
		}
	}
	return strings.Join(lines, "\n")
}
