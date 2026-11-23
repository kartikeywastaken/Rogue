package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Red palette. The ground is set once on the tea.View; every style below is
// foreground-only so nothing ever repaints the ground. The only fill is the
// selected palette row.
var (
	colGround   = lipgloss.Color("#130911") // dark wine-plum
	colSelected = lipgloss.Color("#2E1428")

	colAccent    = lipgloss.Color("#E5484D") // focused borders
	colLogo      = lipgloss.Color("#FF5A5F") // wordmark, assistant label
	colPrompt    = lipgloss.Color("#FF8A80") // input prompt, cursor, user marker
	colText      = lipgloss.Color("#EDE0E0")
	colMuted     = lipgloss.Color("#9A8090")
	colDim       = lipgloss.Color("#6E5868")
	colBorderDim = lipgloss.Color("#4E3448")

	colGreen  = lipgloss.Color("#7EE787") // success only
	colCyan   = lipgloss.Color("#00D7D7")
	colYellow = lipgloss.Color("#F9E2AF")
	colRed    = lipgloss.Color("#FF4040") // errors
)

func fg(c color.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

var (
	stText   = fg(colText)
	stMuted  = fg(colMuted)
	stDim    = fg(colDim)
	stLogo   = fg(colLogo).Bold(true)
	stGreen  = fg(colGreen)
	stPrompt = fg(colPrompt)
	stCyan   = fg(colCyan)
	stYellow = fg(colYellow)
	stRed    = fg(colRed)
	stBold   = fg(colText).Bold(true)
)

func modeColor(mode string) color.Color {
	switch mode {
	case "auto":
		return colYellow
	case "plan":
		return colCyan
	default:
		return colMuted
	}
}
