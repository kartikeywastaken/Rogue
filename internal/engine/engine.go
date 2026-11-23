// Package engine is the seam between Rogue's TUI and the harness behind it.
//
// The TUI only knows about this interface. Swap the Mock for the real harness
// (model client, tool runner, permissions, sessions) without touching the UI.
package engine

import "context"

// Kind identifies what an Event carries.
type Kind int

const (
	// KindText is a streamed chunk of assistant text.
	KindText Kind = iota
	// KindToolStart announces a tool call the agent is about to run.
	KindToolStart
	// KindToolEnd reports a finished tool call (matched by Tool.ID).
	KindToolEnd
	// KindUsage reports cumulative token usage for the turn.
	KindUsage
	// KindNotice is an out-of-band status line from the harness.
	KindNotice
	// KindError ends the turn with a failure.
	KindError
	// KindDone ends the turn successfully.
	KindDone
)

// ToolCall describes one tool invocation.
type ToolCall struct {
	ID     string
	Name   string
	Input  string // short, human-readable summary of the arguments
	Output string // short summary of the result
	OK     bool
}

// Usage is token accounting for the current turn.
type Usage struct {
	Input  int
	Output int
}

// Event is one item on a turn's event stream.
type Event struct {
	Kind  Kind
	Text  string
	Tool  ToolCall
	Usage Usage
	Err   error
}

// Mode is the permission/behaviour mode the user has selected.
type Mode int

const (
	ModeDefault Mode = iota // ask before acting
	ModeAuto                // act without asking
	ModePlan                // read-only planning
)

func (m Mode) String() string {
	switch m {
	case ModeAuto:
		return "auto"
	case ModePlan:
		return "plan"
	default:
		return "default"
	}
}

// Next cycles default → auto → plan → default.
func (m Mode) Next() Mode { return (m + 1) % 3 }

// Request is a single user turn handed to the engine.
type Request struct {
	Prompt string
	Model  string
	Mode   Mode
}

// Engine runs turns. Run must return immediately; the channel is closed after
// a KindDone or KindError event, or when ctx is cancelled.
type Engine interface {
	Name() string
	Models() []string
	Run(ctx context.Context, req Request) <-chan Event
}
