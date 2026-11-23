// Package agent implements the model -> action -> observation execution loop.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/llm"
	"rogue/internal/mission"
)

type EventKind int

const (
	KindText EventKind = iota
	KindToolStart
	KindToolEnd
	KindUsage
	KindNotice
	KindError
	KindDone
)

type ToolInfo struct {
	ID, Name, Input, Output string
	OK                      bool
}
type TokenUsage struct{ Input, Output int }
type Event struct {
	Kind  EventKind
	Text  string
	Tool  ToolInfo
	Usage TokenUsage
	Err   error
}

type Config struct {
	MaxIterations  int
	Model          string
	SystemPrompt   string
	MaxToolCalls   int
	MaxTokens      int
	ToolCategories []string
	AllowedTools   []string
	Runtime        *mission.Runtime
	BeforeTool     func(context.Context, llm.ToolCall) error
	OnStart        func(llm.ToolCall) error
	OnTool         func(Execution) error
}

type Execution struct {
	Call      llm.ToolCall
	Result    *arsenal.Result
	StartedAt time.Time
}

var ErrIterationLimit = errors.New("agent iteration limit reached before completion")
var ErrTokenLimit = errors.New("agent token budget exhausted")
var ErrToolLimit = errors.New("agent tool-call budget exhausted")

type Loop struct {
	llm     llm.Provider
	arsenal *arsenal.Registry
}

func NewLoop(provider llm.Provider, registry *arsenal.Registry) *Loop {
	return &Loop{llm: provider, arsenal: registry}
}
func (loop *Loop) Run(ctx context.Context, config Config, task string) <-chan Event {
	output := make(chan Event, 64)
	go loop.run(ctx, config, task, output)
	return output
}

func begin(ctx context.Context, runtime *mission.Runtime) (context.Context, func(), error) {
	if runtime != nil {
		return runtime.Begin(ctx)
	}
	operation, cancel := context.WithCancel(ctx)
	return operation, cancel, nil
}

type response struct {
	text          string
	calls         []llm.ToolCall
	input, output int
}

func (loop *Loop) ask(ctx context.Context, config Config, messages []llm.Message, tools []llm.ToolDef, totals TokenUsage, emit func(Event) bool) (response, error) {
	var result response
	operation, finish, err := begin(ctx, config.Runtime)
	if err != nil {
		return result, err
	}
	defer finish()
	stream, err := loop.llm.ChatStream(operation, config.Model, messages, tools)
	if err != nil {
		if errors.Is(context.Cause(operation), mission.ErrPaused) {
			return result, mission.ErrPaused
		}
		return result, fmt.Errorf("model request: %w", err)
	}
	completed := false
	var text strings.Builder
	for {
		select {
		case <-operation.Done():
			return result, context.Cause(operation)
		case delta, open := <-stream:
			if !open {
				if operation.Err() != nil {
					return result, context.Cause(operation)
				}
				if !completed {
					return result, errors.New("provider closed stream without completion")
				}
				result.text = text.String()
				return result, nil
			}
			if delta.Err != nil {
				if errors.Is(context.Cause(operation), mission.ErrPaused) {
					return result, mission.ErrPaused
				}
				return result, delta.Err
			}
			if completed {
				return result, errors.New("provider emitted data after completion")
			}
			if delta.Notice != "" && !emit(Event{Kind: KindNotice, Text: delta.Notice}) {
				return result, ctx.Err()
			}
			if delta.Content != "" {
				text.WriteString(delta.Content)
				if !emit(Event{Kind: KindText, Text: delta.Content}) {
					return result, ctx.Err()
				}
			}
			result.input = max(result.input, delta.Usage.PromptTokens)
			result.output = max(result.output, delta.Usage.CompletionTokens)
			if delta.Usage.PromptTokens > 0 || delta.Usage.CompletionTokens > 0 {
				if !emit(Event{Kind: KindUsage, Usage: TokenUsage{Input: totals.Input + result.input, Output: totals.Output + result.output}}) {
					return result, ctx.Err()
				}
			}
			if len(delta.ToolCalls) > 0 {
				result.calls = delta.ToolCalls
			}
			completed = delta.Done
		}
	}
}

func validateCalls(calls []llm.ToolCall, seen map[string]bool) error {
	batch := make(map[string]bool)
	for _, call := range calls {
		var arguments map[string]json.RawMessage
		if call.ID == "" || call.Type != "function" || call.Function.Name == "" || seen[call.ID] || batch[call.ID] || json.Unmarshal([]byte(call.Function.Arguments), &arguments) != nil || arguments == nil {
			return errors.New("invalid or repeated tool call")
		}
		batch[call.ID] = true
	}
	return nil
}

func (loop *Loop) execute(ctx context.Context, config Config, call llm.ToolCall, emit func(Event) bool) (llm.Message, error) {
	operation, finish, err := begin(ctx, config.Runtime)
	if err != nil {
		return llm.Message{}, err
	}
	defer finish()
	input := call.Function.Arguments
	if len(input) > 120 {
		input = input[:120] + "…"
	}
	info := ToolInfo{ID: call.ID, Name: call.Function.Name, Input: input}
	if !emit(Event{Kind: KindToolStart, Tool: info}) {
		return llm.Message{}, ctx.Err()
	}
	if config.OnStart != nil {
		// Write the intent before crossing the network/process boundary. Recovery can
		// then distinguish unfinished work from work that was never dispatched.
		if err := config.OnStart(call); err != nil {
			return llm.Message{}, err
		}
	}
	started := time.Now().UTC()
	var result *arsenal.Result
	if config.BeforeTool != nil {
		err = config.BeforeTool(operation, call)
	}
	if err == nil {
		result, err = loop.arsenal.Exec(operation, call.Function.Name, json.RawMessage(call.Function.Arguments))
	}
	if err != nil {
		result = &arsenal.Result{Success: false, Summary: err.Error(), Error: err.Error(), Dur: time.Since(started)}
	}
	if errors.Is(context.Cause(operation), mission.ErrPaused) {
		result = &arsenal.Result{Success: false, Summary: "operation interrupted by pause; outcome is unknown", Error: mission.ErrPaused.Error(), Dur: time.Since(started)}
	}
	if !result.Success && result.Error == "" {
		result.Error = result.Summary
	}
	data, err := json.Marshal(result)
	if err != nil {
		return llm.Message{}, fmt.Errorf("encode tool result: %w", err)
	}
	if config.OnTool != nil {
		if err := config.OnTool(Execution{Call: call, Result: result, StartedAt: started}); err != nil {
			return llm.Message{}, fmt.Errorf("record tool evidence: %w", err)
		}
	}
	info.OK = result.Success
	info.Output = result.Summary
	if !emit(Event{Kind: KindToolEnd, Tool: info}) {
		return llm.Message{}, ctx.Err()
	}
	return llm.Message{Role: llm.RoleTool, ToolCallID: call.ID, Content: string(data)}, nil
}

func (loop *Loop) run(parent context.Context, config Config, task string, output chan<- Event) {
	defer close(output)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	emit := func(event Event) bool {
		select {
		case output <- event:
			return true
		case <-ctx.Done():
			return false
		}
	}
	fail := func(err error) {
		if err == nil {
			err = errors.New("agent execution interrupted")
		}
		emit(Event{Kind: KindError, Err: err})
	}
	iterations := config.MaxIterations
	if iterations <= 0 {
		iterations = 15
	}
	toolLimit := config.MaxToolCalls
	if toolLimit <= 0 {
		toolLimit = 64
	}
	tokenLimit := config.MaxTokens
	if tokenLimit <= 0 {
		tokenLimit = 50000
	}
	messages := []llm.Message{{Role: llm.RoleSystem, Content: config.SystemPrompt}, {Role: llm.RoleUser, Content: task}}
	tools := loop.arsenal.ToolDefsFor(config.ToolCategories)
	if config.AllowedTools != nil {
		tools = slices.DeleteFunc(tools, func(tool llm.ToolDef) bool { return !slices.Contains(config.AllowedTools, tool.Function.Name) })
	}
	totals := TokenUsage{}
	usedTools := 0
	seen := make(map[string]bool)
	for iteration := range iterations {
		if ctx.Err() != nil {
			return
		}
		reply, err := loop.ask(ctx, config, messages, tools, totals, emit)
		if errors.Is(err, mission.ErrPaused) {
			emit(Event{Kind: KindNotice, Text: "model response interrupted by pause; waiting for resume"})
			continue
		}
		if err != nil {
			fail(err)
			return
		}
		totals.Input += reply.input
		totals.Output += reply.output
		if totals.Input+totals.Output >= tokenLimit {
			fail(ErrTokenLimit)
			return
		}
		if err := validateCalls(reply.calls, seen); err != nil {
			fail(err)
			return
		}
		if usedTools+len(reply.calls) > toolLimit {
			fail(ErrToolLimit)
			return
		}
		messages = append(messages, llm.Message{Role: llm.RoleAssistant, Content: reply.text, ToolCalls: reply.calls})
		if len(reply.calls) == 0 {
			if config.Runtime != nil {
				if err := config.Runtime.Wait(ctx); err != nil {
					fail(err)
					return
				}
			}
			emit(Event{Kind: KindDone})
			return
		}
		for _, call := range reply.calls {
			if ctx.Err() != nil {
				return
			}
			seen[call.ID] = true
			usedTools++
			observation, err := loop.execute(ctx, config, call, emit)
			if err != nil {
				fail(err)
				return
			}
			messages = append(messages, observation)
		}
		emit(Event{Kind: KindNotice, Text: fmt.Sprintf("iteration %d/%d", iteration+1, iterations)})
	}
	fail(ErrIterationLimit)
}
