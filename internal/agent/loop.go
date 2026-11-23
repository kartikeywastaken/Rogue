// Package agent implements the ReAct (Reason-Act-Observe) execution loop that
// drives each operator. It bridges the LLM backbone and the Arsenal, streaming
// events to the caller.
package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
)

// ── events ───────────────────────────────────────────────────────────────────

// EventKind identifies what a Loop event carries.
type EventKind int

const (
	KindText      EventKind = iota // streamed text chunk
	KindToolStart                  // tool call about to execute
	KindToolEnd                    // tool call completed
	KindUsage                      // token accounting
	KindNotice                     // informational status line
	KindError                      // terminal error
	KindDone                       // loop finished successfully
)

// ToolInfo describes one tool invocation for event consumers.
type ToolInfo struct {
	ID     string
	Name   string
	Input  string // human-readable argument summary
	Output string // human-readable result summary
	OK     bool
}

// TokenUsage is input/output token accounting.
type TokenUsage struct{ Input, Output int }

// Event is one item on the loop's event stream.
type Event struct {
	Kind  EventKind
	Text  string
	Tool  ToolInfo
	Usage TokenUsage
	Err   error
}

// ── loop ─────────────────────────────────────────────────────────────────────

// Config tunes the agent loop.
type Config struct {
	MaxIterations int    // 0 means 15
	Model         string // LLM model identifier
	SystemPrompt  string
}

// Loop is a ReAct agent that reasons with an LLM and acts through the Arsenal.
type Loop struct {
	llm     llm.Provider
	arsenal *arsenal.Registry
}

// NewLoop creates a loop backed by the given LLM and tool registry.
func NewLoop(provider llm.Provider, reg *arsenal.Registry) *Loop {
	return &Loop{llm: provider, arsenal: reg}
}

// Run executes the ReAct cycle for the given task. The returned channel
// receives events and is closed when the loop finishes or ctx is cancelled.
func (l *Loop) Run(ctx context.Context, cfg Config, task string) <-chan Event {
	out := make(chan Event, 64)
	go l.run(ctx, cfg, task, out)
	return out
}

func (l *Loop) run(ctx context.Context, cfg Config, task string, out chan<- Event) {
	defer close(out)

	maxIter := cfg.MaxIterations
	if maxIter <= 0 {
		maxIter = 15
	}

	send := func(e Event) bool {
		select {
		case out <- e:
			return true
		case <-ctx.Done():
			return false
		}
	}

	// Build initial messages.
	msgs := []llm.Message{
		{Role: llm.RoleSystem, Content: cfg.SystemPrompt},
		{Role: llm.RoleUser, Content: task},
	}

	tools := l.arsenal.ToolDefs()
	var totalIn, totalOut int

	for iter := range maxIter {
		_ = iter

		// ── LLM call ──
		stream, err := l.llm.ChatStream(ctx, cfg.Model, msgs, tools)
		if err != nil {
			send(Event{Kind: KindError, Err: fmt.Errorf("llm call: %w", err)})
			return
		}

		// Accumulate the assistant's full response.
		var content string
		var toolCalls []llm.ToolCall

		for delta := range stream {
			if ctx.Err() != nil {
				return
			}
			if delta.Content != "" {
				content += delta.Content
				if !send(Event{Kind: KindText, Text: delta.Content}) {
					return
				}
			}
			if delta.Usage.PromptTokens > 0 || delta.Usage.CompletionTokens > 0 {
				totalIn += delta.Usage.PromptTokens
				totalOut += delta.Usage.CompletionTokens
				send(Event{Kind: KindUsage, Usage: TokenUsage{Input: totalIn, Output: totalOut}})
			}
			if len(delta.ToolCalls) > 0 {
				toolCalls = delta.ToolCalls
			}
		}

		// Record the assistant message.
		assistMsg := llm.Message{Role: llm.RoleAssistant, Content: content}
		if len(toolCalls) > 0 {
			assistMsg.ToolCalls = toolCalls
		}
		msgs = append(msgs, assistMsg)

		// ── no tool calls → done ──
		if len(toolCalls) == 0 {
			send(Event{Kind: KindDone})
			return
		}

		// ── execute tool calls ──
		for _, tc := range toolCalls {
			info := ToolInfo{
				ID:   tc.ID,
				Name: tc.Function.Name,
			}

			// Build a short input summary (first 120 chars of args).
			argSummary := tc.Function.Arguments
			if len(argSummary) > 120 {
				argSummary = argSummary[:120] + "…"
			}
			info.Input = argSummary

			if !send(Event{Kind: KindToolStart, Tool: info}) {
				return
			}

			result, err := l.arsenal.Exec(ctx, tc.Function.Name, json.RawMessage(tc.Function.Arguments))

			var toolContent string
			if err != nil {
				info.OK = false
				info.Output = err.Error()
				toolContent = fmt.Sprintf(`{"error": %q}`, err.Error())
			} else {
				info.OK = result.Success
				info.Output = result.Summary
				data, _ := json.Marshal(result.Data)
				toolContent = string(data)
			}

			if !send(Event{Kind: KindToolEnd, Tool: info}) {
				return
			}

			// Append tool result to conversation.
			msgs = append(msgs, llm.Message{
				Role:       llm.RoleTool,
				ToolCallID: tc.ID,
				Content:    toolContent,
			})
		}

		send(Event{Kind: KindNotice, Text: fmt.Sprintf("iteration %d/%d", iter+1, maxIter)})
	}

	send(Event{Kind: KindNotice, Text: "max iterations reached"})
	send(Event{Kind: KindDone})
}
