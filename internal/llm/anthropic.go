package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Anthropic translates our common messages into native Messages API blocks.
// The agent loop never needs provider-specific tool-result or stream formats.
type Anthropic struct {
	APIKey          string
	Endpoint        string
	Client          *http.Client
	MaxOutputTokens int
	Retries         int
}

type anthropicMessage struct {
	Role    string           `json:"role"`
	Content []map[string]any `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []map[string]any   `json:"tools,omitempty"`
	Stream    bool               `json:"stream"`
	MaxTokens int                `json:"max_tokens"`
}

func anthropicBody(model string, messages []Message, tools []ToolDef, limit int) ([]byte, error) {
	request := anthropicRequest{Model: model, Stream: true, MaxTokens: limit}
	for _, message := range messages {
		if message.Role == RoleSystem {
			request.System += message.Content + "\n"
			continue
		}
		role := string(message.Role)
		var blocks []map[string]any
		if message.Role == RoleTool {
			role = "user"
			result := map[string]any{"type": "tool_result", "tool_use_id": message.ToolCallID, "content": message.Content}
			var outcome struct {
				Success *bool `json:"success"`
			}
			if json.Unmarshal([]byte(message.Content), &outcome) == nil && outcome.Success != nil {
				result["is_error"] = !*outcome.Success
			}
			blocks = append(blocks, result)
		} else {
			if message.Content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": message.Content})
			}
			for _, call := range message.ToolCalls {
				var input map[string]any
				if err := json.Unmarshal([]byte(call.Function.Arguments), &input); err != nil || input == nil {
					return nil, errors.New("invalid tool input for Anthropic")
				}
				blocks = append(blocks, map[string]any{"type": "tool_use", "id": call.ID, "name": call.Function.Name, "input": input})
			}
		}
		if role != "user" && role != "assistant" {
			return nil, errors.New("unsupported Anthropic message role")
		}
		if len(blocks) == 0 {
			continue
		}
		last := len(request.Messages) - 1
		if last >= 0 && request.Messages[last].Role == role {
			request.Messages[last].Content = append(request.Messages[last].Content, blocks...)
		} else {
			request.Messages = append(request.Messages, anthropicMessage{Role: role, Content: blocks})
		}
	}
	for _, tool := range tools {
		request.Tools = append(request.Tools, map[string]any{"name": tool.Function.Name, "description": tool.Function.Description, "input_schema": tool.Function.Parameters})
	}
	return json.Marshal(request)
}

func (provider *Anthropic) ChatStream(ctx context.Context, model string, messages []Message, tools []ToolDef) (<-chan StreamDelta, error) {
	limit := provider.MaxOutputTokens
	if limit <= 0 {
		limit = 2048
	}
	body, err := anthropicBody(model, messages, tools, limit)
	if err != nil {
		return nil, err
	}
	client := provider.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	response, allowance, err := post(ctx, client, provider.Retries, limit, body, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.Endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "text/event-stream")
		request.Header.Set("x-api-key", provider.APIKey)
		request.Header.Set("anthropic-version", "2026-10-21")
		return request, nil
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		allowance.finish(Usage{}, false)
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		message := string(body)
		if provider.APIKey != "" {
			message = strings.ReplaceAll(message, provider.APIKey, "[redacted]")
		}
		return nil, &HTTPError{Provider: "anthropic", Status: response.StatusCode, Message: message}
	}
	output := make(chan StreamDelta, 64)
	go readAnthropic(ctx, response.Body, output)
	return account(ctx, output, allowance), nil
}

type anthropicUsage struct {
	Input        int `json:"input_tokens"`
	Output       int `json:"output_tokens"`
	CacheCreated int `json:"cache_creation_input_tokens"`
	CacheRead    int `json:"cache_read_input_tokens"`
}

type anthropicEvent struct {
	Type    string `json:"type"`
	Index   int    `json:"index"`
	Message struct {
		Usage anthropicUsage `json:"usage"`
	} `json:"message"`
	Block struct {
		Type  string          `json:"type"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Text  string          `json:"text"`
		Input json.RawMessage `json:"input"`
	} `json:"content_block"`
	Delta struct {
		Type       string `json:"type"`
		Text       string `json:"text"`
		JSON       string `json:"partial_json"`
		StopReason string `json:"stop_reason"`
	} `json:"delta"`
	Usage anthropicUsage `json:"usage"`
}

func readAnthropic(ctx context.Context, body io.ReadCloser, output chan<- StreamDelta) {
	defer close(output)
	defer body.Close()
	send := func(delta StreamDelta) bool {
		select {
		case output <- delta:
			return true
		case <-ctx.Done():
			return false
		}
	}
	fail := func(err error) { send(StreamDelta{Err: err}) }
	type block struct {
		kind, id, name, input, arguments string
		closed                           bool
	}
	blocks := make(map[int]*block)
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	started := false
	stopReason := ""
	usage := Usage{}
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var event anthropicEvent
		if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &event); err != nil {
			fail(err)
			return
		}
		switch event.Type {
		case "ping":
			continue
		case "error":
			fail(errors.New("Anthropic reported an error during streaming"))
			return
		case "message_start":
			if started {
				fail(errors.New("duplicate Anthropic message start"))
				return
			}
			started = true
			usage.PromptTokens = event.Message.Usage.Input + event.Message.Usage.CacheCreated + event.Message.Usage.CacheRead
			usage.CompletionTokens = event.Message.Usage.Output
		case "content_block_start":
			if !started || event.Index < 0 || event.Index > 127 || blocks[event.Index] != nil {
				fail(errors.New("invalid Anthropic content block"))
				return
			}
			blocks[event.Index] = &block{kind: event.Block.Type, id: event.Block.ID, name: event.Block.Name, input: string(event.Block.Input)}
			if event.Block.Type == "text" && event.Block.Text != "" {
				if !send(StreamDelta{Content: event.Block.Text}) {
					return
				}
			}
		case "content_block_delta":
			current := blocks[event.Index]
			if current == nil || current.closed {
				fail(errors.New("delta for an unopened Anthropic block"))
				return
			}
			switch event.Delta.Type {
			case "text_delta":
				if current.kind != "text" {
					fail(errors.New("text delta belongs to a non-text Anthropic block"))
					return
				}
				if !send(StreamDelta{Content: event.Delta.Text}) {
					return
				}
			case "input_json_delta":
				if current.kind != "tool_use" {
					fail(errors.New("tool input belongs to a non-tool Anthropic block"))
					return
				}
				current.arguments += event.Delta.JSON
				if len(current.arguments) > 1024*1024 {
					fail(errors.New("Anthropic tool input exceeded limit"))
					return
				}
			}
		case "content_block_stop":
			current := blocks[event.Index]
			if current == nil || current.closed {
				fail(errors.New("invalid Anthropic block termination"))
				return
			}
			current.closed = true
		case "message_delta":
			if event.Delta.StopReason != "" {
				stopReason = event.Delta.StopReason
			}
			usage.PromptTokens = max(usage.PromptTokens, event.Usage.Input+event.Usage.CacheCreated+event.Usage.CacheRead)
			usage.CompletionTokens = max(usage.CompletionTokens, event.Usage.Output)
		case "message_stop":
			if !started || (stopReason != "end_turn" && stopReason != "tool_use") {
				fail(fmt.Errorf("incomplete Anthropic response: %s", stopReason))
				return
			}
			indices := make([]int, 0, len(blocks))
			for index := range blocks {
				indices = append(indices, index)
			}
			sort.Ints(indices)
			var calls []ToolCall
			seen := make(map[string]bool)
			for _, index := range indices {
				current := blocks[index]
				if !current.closed {
					fail(errors.New("Anthropic content block was not completed"))
					return
				}
				if current.kind != "tool_use" {
					continue
				}
				arguments := current.arguments
				if arguments == "" {
					arguments = current.input
				}
				var object map[string]json.RawMessage
				if current.id == "" || current.name == "" || seen[current.id] || json.Unmarshal([]byte(arguments), &object) != nil || object == nil {
					fail(errors.New("invalid Anthropic tool call"))
					return
				}
				seen[current.id] = true
				calls = append(calls, ToolCall{ID: current.id, Type: "function", Function: FuncCall{Name: current.name, Arguments: arguments}})
			}
			if (stopReason == "tool_use") != (len(calls) > 0) {
				fail(errors.New("Anthropic stop reason disagrees with tool calls"))
				return
			}
			send(StreamDelta{Done: true, ToolCalls: calls, Usage: usage})
			return
		}
	}
	if ctx.Err() == nil {
		if err := scanner.Err(); err != nil {
			fail(err)
		} else {
			fail(errors.New("Anthropic stream ended before message_stop"))
		}
	}
}
