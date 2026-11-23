package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const openRouterURL = "https://openrouter.ai/api/v1/chat/completions"

// OpenRouter implements Provider using the OpenRouter API (OpenAI-compatible).
type OpenRouter struct {
	APIKey string
	Client *http.Client
}

// NewOpenRouter creates a provider with the given API key.
func NewOpenRouter(apiKey string) *OpenRouter {
	return &OpenRouter{APIKey: apiKey, Client: http.DefaultClient}
}

// ── request / response wire types ────────────────────────────────────────────

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Tools    []ToolDef `json:"tools,omitempty"`
	Stream   bool      `json:"stream"`
}

type sseChoice struct {
	Delta        sseDelta `json:"delta"`
	FinishReason *string  `json:"finish_reason,omitempty"`
}

type sseDelta struct {
	Role      string          `json:"role,omitempty"`
	Content   string          `json:"content,omitempty"`
	ToolCalls json.RawMessage `json:"tool_calls,omitempty"`
}

type sseChunk struct {
	Choices []sseChoice `json:"choices"`
	Usage   *Usage      `json:"usage,omitempty"`
}

type sseToolCallDelta struct {
	Index    int      `json:"index"`
	ID       string   `json:"id,omitempty"`
	Type     string   `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	} `json:"function"`
}

// ── streaming ────────────────────────────────────────────────────────────────

func (o *OpenRouter) ChatStream(ctx context.Context, model string, msgs []Message, tools []ToolDef) (<-chan StreamDelta, error) {
	body, err := json.Marshal(chatRequest{
		Model:    model,
		Messages: msgs,
		Tools:    tools,
		Stream:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", openRouterURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.APIKey)
	req.Header.Set("HTTP-Referer", "https://github.com/rogue-harness")
	req.Header.Set("X-Title", "ROGUE")

	resp, err := o.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("openrouter %d: %s", resp.StatusCode, truncate(string(b), 300))
	}

	out := make(chan StreamDelta, 64)
	go o.readSSE(ctx, resp.Body, out)
	return out, nil
}

func (o *OpenRouter) readSSE(ctx context.Context, body io.ReadCloser, out chan<- StreamDelta) {
	defer close(out)
	defer body.Close()

	// Accumulators for tool calls across chunks.
	type pending struct {
		id   string
		name string
		args strings.Builder
	}
	calls := map[int]*pending{}

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	send := func(d StreamDelta) bool {
		select {
		case out <- d:
			return true
		case <-ctx.Done():
			return false
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var chunk sseChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}

		for _, ch := range chunk.Choices {
			// Text content.
			if ch.Delta.Content != "" {
				if !send(StreamDelta{Content: ch.Delta.Content}) {
					return
				}
			}

			// Tool call deltas.
			if len(ch.Delta.ToolCalls) > 0 {
				var deltas []sseToolCallDelta
				if err := json.Unmarshal(ch.Delta.ToolCalls, &deltas); err != nil {
					continue
				}
				for _, d := range deltas {
					p, ok := calls[d.Index]
					if !ok {
						p = &pending{}
						calls[d.Index] = p
					}
					if d.ID != "" {
						p.id = d.ID
					}
					if d.Function.Name != "" {
						p.name = d.Function.Name
					}
					p.args.WriteString(d.Function.Arguments)
				}
			}
		}

		// Forward usage if present.
		if chunk.Usage != nil {
			if !send(StreamDelta{Usage: *chunk.Usage}) {
				return
			}
		}
	}

	// Emit accumulated tool calls.
	if len(calls) > 0 {
		var tcs []ToolCall
		for i := 0; i < len(calls); i++ {
			p := calls[i]
			tcs = append(tcs, ToolCall{
				ID:   p.id,
				Type: "function",
				Function: FuncCall{
					Name:      p.name,
					Arguments: p.args.String(),
				},
			})
		}
		send(StreamDelta{ToolCalls: tcs, Done: true})
	} else {
		send(StreamDelta{Done: true})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
