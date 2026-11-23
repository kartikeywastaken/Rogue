package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"rogue/internal/domain"
)

type Capabilities struct {
	Model         string
	Streaming     bool
	ToolCalling   bool
	ToolResults   bool
	UsageReported bool
	CheckedAt     time.Time
}

// Probe tests one configured model with a harmless echo tool. No target network
// request is executed. This is explicit because hosted probes can incur usage.
func Probe(ctx context.Context, provider Provider, model string) (Capabilities, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := Capabilities{Model: model, CheckedAt: time.Now().UTC()}
	token := domain.ID()
	tool := ToolDef{Type: "function", Function: FuncDef{Name: "verify_echo", Description: "Return the supplied verification token", Parameters: map[string]any{"type": "object", "properties": map[string]any{"token": map[string]any{"type": "string"}}, "required": []string{"token"}}}}
	messages := []Message{{Role: RoleSystem, Content: "This is a capability check. Call verify_echo exactly once using the supplied token. After its result, repeat the token in your final answer."}, {Role: RoleUser, Content: "Verify using token " + token}}
	stream, err := provider.ChatStream(ctx, model, messages, []ToolDef{tool})
	if err != nil {
		return result, err
	}
	var calls []ToolCall
	complete := false
	for delta := range stream {
		if delta.Err != nil {
			return result, delta.Err
		}
		result.Streaming = true
		result.UsageReported = result.UsageReported || delta.Usage.PromptTokens > 0
		if delta.Done {
			complete = true
			calls = delta.ToolCalls
		}
	}
	if !complete || len(calls) != 1 || calls[0].Function.Name != "verify_echo" {
		return result, errors.New("model did not complete the verification tool request")
	}
	var arguments struct {
		Token string `json:"token"`
	}
	if json.Unmarshal([]byte(calls[0].Function.Arguments), &arguments) != nil || arguments.Token != token {
		return result, errors.New("model supplied incorrect verification arguments")
	}
	result.ToolCalling = true
	messages = append(messages, Message{Role: RoleAssistant, ToolCalls: calls}, Message{Role: RoleTool, ToolCallID: calls[0].ID, Content: fmt.Sprintf(`{"token":%q}`, token)})
	stream, err = provider.ChatStream(ctx, model, messages, nil)
	if err != nil {
		return result, err
	}
	var answer strings.Builder
	complete = false
	for delta := range stream {
		if delta.Err != nil {
			return result, delta.Err
		}
		answer.WriteString(delta.Content)
		result.UsageReported = result.UsageReported || delta.Usage.PromptTokens > 0
		if delta.Done {
			complete = true
		}
	}
	if !complete || !strings.Contains(answer.String(), token) {
		return result, errors.New("model did not use the tool result correctly")
	}
	result.ToolResults = true
	return result, nil
}
