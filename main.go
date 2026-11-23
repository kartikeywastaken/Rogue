// Rogue — a terminal agent harness.
package main

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"

	"rogue/internal/engine"
	"rogue/internal/tui"
)

func main() {
	// Replace engine.NewMock() with the real harness once it implements
	// engine.Engine.
	p := tea.NewProgram(tui.New(engine.NewMock()))
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "rogue:", err)
		os.Exit(1)
	}
}
