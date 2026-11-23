// Rogue — a terminal agent harness.
package main

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"

	"rogue/internal/arsenal"
	"rogue/internal/engine"
	"rogue/internal/llm"
	"rogue/internal/tui"
)

// models is the default set offered to the user in the model picker.
var models = []string{
	"anthropic/claude-sonnet-4",
	"anthropic/claude-haiku-4",
	"google/gemini-2.5-flash",
	"openai/gpt-4o",
	"openai/gpt-4o-mini",
	"deepseek/deepseek-chat-v3-0324",
}

func main() {
	eng := buildEngine()
	p := tea.NewProgram(tui.New(eng))
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "rogue:", err)
		os.Exit(1)
	}
}

func buildEngine() engine.Engine {
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey == "" {
		// No API key — fall back to the mock so the TUI still works.
		return engine.NewMock()
	}

	provider := llm.NewOpenRouter(apiKey)

	reg := arsenal.New()
	arsenal.RegisterReconTools(reg)

	defModel := os.Getenv("ROGUE_MODEL")
	if defModel == "" {
		defModel = models[0]
	}

	return engine.NewHarness(provider, reg, models, defModel)
}
