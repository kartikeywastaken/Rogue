// Package mcp provides a Model Context Protocol JSON-RPC 2.0 stdio server.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"rogue/internal/arsenal"
	"rogue/internal/engine"
	"rogue/internal/operator"
	"rogue/internal/storage"
	"rogue/internal/telemetry"
)

// ── JSON-RPC 2.0 types ──────────────────────────────────────────────────────

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// ── server ───────────────────────────────────────────────────────────────────

type Server struct {
	harness  *engine.Harness
	registry *arsenal.Registry
	store    *storage.Store
	writer   *json.Encoder
}

func New(harness *engine.Harness, registry *arsenal.Registry, store *storage.Store) *Server {
	return &Server{harness: harness, registry: registry, store: store, writer: json.NewEncoder(os.Stdout)}
}

func (s *Server) Run(ctx context.Context) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.send(Response{JSONRPC: "2.0", Error: &RPCError{Code: -32700, Message: "parse error: " + err.Error()}})
			continue
		}
		resp := s.handle(ctx, req)
		if resp == nil {
			continue // notification, no response
		}
		s.send(*resp)
	}
	return scanner.Err()
}

func (s *Server) send(resp Response) {
	resp.JSONRPC = "2.0"
	_ = s.writer.Encode(resp)
}

func (s *Server) handle(ctx context.Context, req Request) *Response {
	// Notifications (no ID) don't get responses
	isNotification := req.ID == nil || string(req.ID) == "" || string(req.ID) == "null"
	respond := func(result any) *Response {
		if isNotification {
			return nil
		}
		return &Response{ID: req.ID, Result: result}
	}
	respondError := func(code int, msg string) *Response {
		if isNotification {
			return nil
		}
		return &Response{ID: req.ID, Error: &RPCError{Code: code, Message: msg}}
	}

	switch req.Method {
	case "initialize":
		return respond(map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":   map[string]any{"tools": map[string]any{}, "resources": map[string]any{}},
			"serverInfo":     map[string]any{"name": "rogue", "version": telemetry.DefaultBuildInfo().Version},
		})

	case "notifications/initialized":
		return nil // no-op notification

	case "tools/list":
		tools := s.registry.All()
		var mcpTools []map[string]any
		for _, t := range tools {
			if t.Available != nil && t.Available() != nil {
				continue
			}
			mcpTools = append(mcpTools, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": t.Parameters,
			})
		}
		return respond(map[string]any{"tools": mcpTools})

	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return respondError(-32602, "invalid params: "+err.Error())
		}
		if params.Arguments == nil {
			params.Arguments = json.RawMessage("{}")
		}
		// Supply a permissive internal policy so offline tools (Base64, JWT,
		// research organs, etc.) pass authorization. MCP callers take
		// responsibility for the tools they invoke; scope is unrestricted here.
		execCtx := arsenal.WithPolicy(ctx, arsenal.Policy{Mode: "auto"})
		result, err := s.registry.Exec(execCtx, params.Name, params.Arguments)
		if err != nil {
			return respond(map[string]any{
				"content": []map[string]any{{"type": "text", "text": err.Error()}},
				"isError": true,
			})
		}
		data, _ := json.Marshal(result)
		return respond(map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(data)}},
			"isError": false,
		})

	case "resources/list":
		resources := []map[string]any{
			{"uri": "rogue://missions", "name": "Mission List", "description": "Saved assessment missions", "mimeType": "application/json"},
			{"uri": "rogue://config", "name": "Configuration", "description": "Current ROGUE configuration", "mimeType": "application/json"},
			{"uri": "rogue://tools", "name": "Tool Catalog", "description": "Available assessment tools", "mimeType": "application/json"},
			{"uri": "rogue://operators", "name": "Operator Profiles", "description": "Eight operator archetypes", "mimeType": "application/json"},
		}
		return respond(map[string]any{"resources": resources})

	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return respondError(-32602, "invalid params: "+err.Error())
		}
		content, mimeType, err := s.readResource(params.URI)
		if err != nil {
			return respondError(-32602, err.Error())
		}
		return respond(map[string]any{
			"contents": []map[string]any{{"uri": params.URI, "mimeType": mimeType, "text": content}},
		})

	default:
		return respondError(-32601, fmt.Sprintf("method not found: %s", req.Method))
	}
}

func (s *Server) readResource(uri string) (string, string, error) {
	switch {
	case uri == "rogue://missions":
		if s.store == nil {
			return "[]", "application/json", nil
		}
		missions, err := s.store.List()
		if err != nil {
			return "", "", err
		}
		data, _ := json.MarshalIndent(missions, "", "  ")
		return string(data), "application/json", nil

	case uri == "rogue://config":
		data, _ := json.MarshalIndent(telemetry.SummarizeConfig(), "", "  ")
		return string(data), "application/json", nil

	case uri == "rogue://tools":
		data, _ := json.MarshalIndent(s.registry.Catalog(), "", "  ")
		return string(data), "application/json", nil

	case uri == "rogue://operators":
		type profile struct {
			Archetype string   `json:"archetype"`
			Callsign  string   `json:"callsign"`
			Phase     string   `json:"phase"`
			ToolCats  []string `json:"tool_categories"`
		}
		var profiles []profile
		for _, p := range operator.Profiles() {
			profiles = append(profiles, profile{Archetype: string(p.Archetype), Callsign: p.Callsign, Phase: string(p.Phase), ToolCats: p.ToolCats})
		}
		data, _ := json.MarshalIndent(profiles, "", "  ")
		return string(data), "application/json", nil

	case strings.HasPrefix(uri, "rogue://missions/"):
		id := strings.TrimPrefix(uri, "rogue://missions/")
		report, err := s.harness.Report(id)
		if err != nil {
			return "", "", err
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		return string(data), "application/json", nil

	default:
		return "", "", fmt.Errorf("unknown resource: %s", uri)
	}
}


