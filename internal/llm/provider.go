// Package llm provides the LLM backbone: a provider interface and message
// types for chat completions with tool calling.
package llm

import "context"

// ── messages ─────────────────────────────────────────────────────────────────

// Role is a chat message role.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// Message is one turn in a conversation.
type Message struct {
	Role       Role       `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall is a function invocation requested by the model.
type ToolCall struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"` // always "function"
	Function FuncCall `json:"function"`
}

// FuncCall is the name + arguments of a tool call.
type FuncCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // raw JSON string
}

// ── tool definitions ─────────────────────────────────────────────────────────

// ToolDef describes a tool the model can call. Parameters is a JSON Schema
// object (map representation).
type ToolDef struct {
	Type     string      `json:"type"` // "function"
	Function FuncDef     `json:"function"`
}

// FuncDef is a tool's function definition.
type FuncDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// ── responses ────────────────────────────────────────────────────────────────

// Usage is token accounting.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// StreamDelta is one chunk from a streaming completion.
type StreamDelta struct {
	Content   string     // text fragment
	ToolCalls []ToolCall // partial tool call deltas
	Done      bool       // stream finished
	Usage     Usage
}

// ── provider ─────────────────────────────────────────────────────────────────

// Provider is the interface every LLM backend implements.
type Provider interface {
	// ChatStream sends a chat completion request and streams deltas back.
	// The returned channel is closed when the response is complete or ctx
	// is cancelled.
	ChatStream(ctx context.Context, model string, msgs []Message, tools []ToolDef) (<-chan StreamDelta, error)
}
