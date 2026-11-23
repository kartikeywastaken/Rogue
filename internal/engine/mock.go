package engine

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Mock is a stand-in engine that streams a canned reply with a fake tool call,
// so the TUI can be exercised before the real harness exists.
type Mock struct{}

func NewMock() *Mock { return &Mock{} }

func (*Mock) Name() string { return "mock" }

func (*Mock) Models() []string {
	return []string{"rogue-dev", "rogue-fast", "rogue-deep"}
}

func (*Mock) Run(ctx context.Context, req Request) <-chan Event {
	out := make(chan Event)
	go func() {
		defer close(out)
		send := func(e Event) bool {
			select {
			case out <- e:
				return true
			case <-ctx.Done():
				return false
			}
		}
		pause := func(d time.Duration) bool {
			select {
			case <-time.After(d):
				return true
			case <-ctx.Done():
				return false
			}
		}

		in := len(strings.Fields(req.Prompt)) * 4
		outTok := 0
		stream := func(text string) bool {
			for _, w := range strings.SplitAfter(text, " ") {
				if !send(Event{Kind: KindText, Text: w}) {
					return false
				}
				outTok++
				if !send(Event{Kind: KindUsage, Usage: Usage{Input: in, Output: outTok}}) {
					return false
				}
				if !pause(28 * time.Millisecond) {
					return false
				}
			}
			return true
		}

		if !pause(450*time.Millisecond) ||
			!stream(fmt.Sprintf("Looking into that. I'm running in %s mode on %s, so I'll take a quick look around first. ", req.Mode, req.Model)) {
			return
		}

		tool := ToolCall{ID: "t1", Name: "list_files", Input: "."}
		if !send(Event{Kind: KindToolStart, Tool: tool}) || !pause(900*time.Millisecond) {
			return
		}
		tool.Output, tool.OK = "3 entries", true
		if !send(Event{Kind: KindToolEnd, Tool: tool}) {
			return
		}

		reply := "This is the mock engine, so nothing real happened. " +
			"Wire your harness in by implementing engine.Engine and passing it to tui.New in main.go. " +
			"You asked: \"" + req.Prompt + "\""
		if !stream(reply) {
			return
		}
		send(Event{Kind: KindDone})
	}()
	return out
}
