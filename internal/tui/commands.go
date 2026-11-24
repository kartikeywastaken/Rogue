package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"

	"rogue/internal/engine"
)

type command struct {
	name string
	desc string
}

var commands = []command{
	{"/help", "Show commands and keys"},
	{"/model", "Choose the model"},
	{"/provider", "Change provider, API key, or model"},
	{"/mode", "Cycle mode: default · auto · plan"},
	{"/clear", "Clear the transcript"},
	{"/new", "Start a fresh session"},
	{"/quit", "Exit Rogue"},
}

// paletteItems returns the commands matching the input while the user is
// typing a bare slash command, or nil when the palette should be closed.
func (m Model) paletteItems() []command {
	v := m.input.Value()
	if m.picker || !strings.HasPrefix(v, "/") || strings.ContainsAny(v, " \n") {
		return nil
	}
	q := strings.ToLower(strings.TrimPrefix(v, "/"))
	out := []command{}
	for _, c := range commands {
		if strings.Contains(c.name[1:], q) || (q != "" && strings.Contains(strings.ToLower(c.desc), q)) {
			out = append(out, c)
		}
	}
	return out
}

func (m Model) runCommand(input string) (Model, tea.Cmd) {
	name, _, _ := strings.Cut(strings.TrimSpace(input), " ")
	switch name {
	case "/help":
		m.phase = phaseSession
		m.push(entry{kind: entNotice, text: "commands"})
		for _, c := range commands {
			m.push(entry{kind: entNotice, text: padRight(c.name, 9) + c.desc})
		}
		m.push(entry{kind: entNotice, text: "keys"})
		for _, k := range [][2]string{
			{"enter", "send"},
			{"shift+enter", "newline (also alt+enter, ctrl+j)"},
			{"shift+tab", "cycle mode"},
			{"esc", "interrupt the running turn"},
			{"↑ ↓", "prompt history"},
			{"pgup pgdn", "scroll transcript (or mouse wheel)"},
			{"ctrl+c", "quit"},
		} {
			m.push(entry{kind: entNotice, text: padRight(k[0], 12) + k[1]})
		}
	case "/model":
		m.picker = true
		m.pickIdx = 0
		for i, md := range m.eng.Models() {
			if md == m.model {
				m.pickIdx = i
			}
		}
	case "/provider", "/login", "/setup":
		return m, m.openSetup()
	case "/mode":
		m.mode = m.mode.Next()
		m.notice("mode → " + m.mode.String())
	case "/clear":
		m.stopTurn()
		m.entries = nil
		m.notice("transcript cleared")
	case "/new":
		m.stopTurn()
		m.entries = nil
		m.total, m.usage = engine.Usage{}, engine.Usage{}
		m.phase = phaseLanding
	case "/quit", "/exit":
		m.stopTurn()
		return m, tea.Quit
	default:
		m.flash = "unknown command " + name + " · /help lists them"
	}
	return m, nil
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s + " "
	}
	return s + strings.Repeat(" ", n-len(s))
}
