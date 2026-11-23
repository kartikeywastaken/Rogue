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

// Client implements the common Chat Completions protocol. Provider-specific
// configuration stays outside the agent loop; no runtime mock is available.
type Client struct {
	Name, APIKey, Endpoint string
	Client                 *http.Client
	MaxOutputTokens        int
	Retries                int
}

func NewOpenRouter(key string) *Client {
	return &Client{Name: "openrouter", APIKey: key, Endpoint: "https://openrouter.ai/api/v1/chat/completions", Client: &http.Client{Timeout: 90 * time.Second}}
}

type chatRequest struct {
	Model               string          `json:"model"`
	Messages            []Message       `json:"messages"`
	Tools               []ToolDef       `json:"tools,omitempty"`
	Stream              bool            `json:"stream"`
	StreamOptions       map[string]bool `json:"stream_options"`
	MaxTokens           int             `json:"max_tokens,omitempty"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
}
type sseToolCallDelta struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}
type sseChunk struct {
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Content   string             `json:"content"`
			ToolCalls []sseToolCallDelta `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *Usage          `json:"usage"`
	Error json.RawMessage `json:"error"`
}

func (c *Client) ChatStream(ctx context.Context, model string, msgs []Message, tools []ToolDef) (<-chan StreamDelta, error) {
	limit := c.MaxOutputTokens
	if limit <= 0 {
		limit = 2048
	}
	requestBody := chatRequest{Model: model, Messages: msgs, Tools: tools, Stream: true, StreamOptions: map[string]bool{"include_usage": true}}
	if c.Name == "openai" {
		requestBody.MaxCompletionTokens = limit
	} else {
		requestBody.MaxTokens = limit
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if c.Name == "openrouter" {
		req.Header.Set("X-Title", "ROGUE")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	resp, allowance, err := post(ctx, client, c.Retries, limit, body, func() (*http.Request, error) {
		request := req.Clone(ctx)
		request.Body = io.NopCloser(bytes.NewReader(body))
		return request, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s request: %w", c.Name, err)
	}
	if resp.StatusCode != http.StatusOK {
		allowance.finish(Usage{}, false)
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		// Never include the request or Authorization header in diagnostic output.
		message := string(b)
		if c.APIKey != "" {
			message = strings.ReplaceAll(message, c.APIKey, "[redacted]")
		}
		return nil, &HTTPError{Provider: c.Name, Status: resp.StatusCode, Message: message}
	}
	out := make(chan StreamDelta, 64)
	go c.readSSE(ctx, resp.Body, out)
	return account(ctx, out, allowance), nil
}

func (c *Client) readSSE(ctx context.Context, body io.ReadCloser, out chan<- StreamDelta) {
	defer close(out)
	defer body.Close()
	send := func(d StreamDelta) bool {
		select {
		case out <- d:
			return true
		case <-ctx.Done():
			return false
		}
	}
	fail := func(err error) { send(StreamDelta{Err: err}) }
	type pending struct{ id, name, args string }
	calls := map[int]*pending{}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	finished := false
	reason := ""
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			if !finished {
				fail(errors.New("stream ended without a finish reason"))
				return
			}
			break
		}
		var chunk sseChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			fail(fmt.Errorf("invalid stream JSON: %w", err))
			return
		}
		if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
			fail(errors.New("provider reported an error during streaming"))
			return
		}
		for _, ch := range chunk.Choices {
			if ch.Index != 0 {
				continue
			}
			if finished && (ch.Delta.Content != "" || len(ch.Delta.ToolCalls) > 0) {
				fail(errors.New("content after stream finish"))
				return
			}
			if ch.Delta.Content != "" && !send(StreamDelta{Content: ch.Delta.Content}) {
				return
			}
			for _, d := range ch.Delta.ToolCalls {
				if d.Index < 0 || d.Index > 127 {
					fail(errors.New("tool index outside supported range"))
					return
				}
				if d.Type != "" && d.Type != "function" {
					fail(errors.New("unsupported tool call type"))
					return
				}
				p := calls[d.Index]
				if p == nil {
					p = &pending{}
					calls[d.Index] = p
				}
				if d.ID != "" {
					if p.id != "" && p.id != d.ID {
						fail(errors.New("tool call ID changed during streaming"))
						return
					}
					p.id = d.ID
				}
				p.name += d.Function.Name
				p.args += d.Function.Arguments
				if len(p.args) > 1024*1024 {
					fail(errors.New("tool arguments exceed size limit"))
					return
				}
			}
			if ch.FinishReason != nil {
				finished = true
				reason = *ch.FinishReason
			}
		}
		if chunk.Usage != nil && !send(StreamDelta{Usage: *chunk.Usage}) {
			return
		}
	}
	if ctx.Err() != nil {
		return
	}
	if err := scanner.Err(); err != nil {
		fail(fmt.Errorf("read stream: %w", err))
		return
	}
	if !finished {
		fail(errors.New("unexpected EOF before stream completion"))
		return
	}
	if reason != "stop" && reason != "tool_calls" {
		fail(fmt.Errorf("incomplete response: finish reason %q", reason))
		return
	}
	if (reason == "tool_calls") != (len(calls) > 0) {
		fail(errors.New("finish reason does not match tool calls"))
		return
	}
	indices := make([]int, 0, len(calls))
	for i := range calls {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	var complete []ToolCall
	seen := map[string]bool{}
	for _, i := range indices {
		p := calls[i]
		var obj map[string]json.RawMessage
		if p.id == "" || p.name == "" || seen[p.id] || json.Unmarshal([]byte(p.args), &obj) != nil || obj == nil {
			fail(errors.New("incomplete or invalid tool call"))
			return
		}
		seen[p.id] = true
		complete = append(complete, ToolCall{ID: p.id, Type: "function", Function: FuncCall{Name: p.name, Arguments: p.args}})
	}
	send(StreamDelta{ToolCalls: complete, Done: true})
}
