// Package arsenal provides the tool registry and execution layer. Tools are
// registered with typed parameter schemas and execute real operations.
package arsenal

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"rogue/internal/domain"
	"rogue/internal/llm"
)

// ── tool interface ───────────────────────────────────────────────────────────

// Tool is a single executable capability.
type Tool struct {
	Name          string
	Category      string // recon, web, vuln, auth, util
	Description   string
	Parameters    map[string]any // JSON Schema for the LLM
	Execute       func(ctx context.Context, args json.RawMessage) (*Result, error)
	Available     func() error
	LabOnly       bool
	Internal      bool
	SensitiveArgs []string
}

// Result is the output of a tool execution.
type Result struct {
	Success      bool                `json:"success"`
	Data         any                 `json:"data,omitempty"`
	Summary      string              `json:"summary"`
	Error        string              `json:"error,omitempty"`
	Findings     []domain.Finding    `json:"-"` // proposals; the vault attaches real observations
	Artifact     []byte              `json:"-"` // original output for the protected vault, not model context
	ArtifactType string              `json:"-"`
	Dur          time.Duration       `json:"duration_ns"`
	Credentials  []domain.Credential `json:"-"`
}

// ── registry ─────────────────────────────────────────────────────────────────

// Registry holds registered tools and provides lookup + execution.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*Tool
}

// New creates an empty tool registry.
func New() *Registry {
	return &Registry{tools: make(map[string]*Tool)}
}

// Register adds a tool. Panics on duplicate names.
func (r *Registry) Register(t *Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.tools[t.Name]; dup {
		panic("arsenal: duplicate tool " + t.Name)
	}
	r.tools[t.Name] = t
}

// Get returns a tool by name, or nil.
func (r *Registry) Get(name string) *Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tools[name]
}

// All returns every registered tool.
func (r *Registry) All() []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	return out
}

// ByCategory returns tools in the given category.
func (r *Registry) ByCategory(cat string) []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Tool
	for _, t := range r.tools {
		if t.Category == cat {
			out = append(out, t)
		}
	}
	return out
}

// Exec runs a tool by name with the given JSON arguments.
func (r *Registry) Exec(ctx context.Context, name string, args json.RawMessage) (*Result, error) {
	t := r.Get(name)
	if t == nil {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	if t.Available != nil {
		if err := t.Available(); err != nil {
			return nil, err
		}
	}
	if err := validateArgs(args, t.Parameters); err != nil {
		return nil, err
	}
	if err := authorize(ctx, t, args); err != nil {
		return nil, err
	}
	start := time.Now()
	res, err := t.Execute(ctx, args)
	if err != nil {
		return &Result{Success: false, Summary: err.Error(), Error: err.Error(), Dur: time.Since(start)}, err
	}
	if res == nil {
		return nil, fmt.Errorf("tool %q returned no result", name)
	}
	if !res.Success && res.Error == "" {
		res.Error = res.Summary
	}
	res.Dur = time.Since(start)
	return res, nil
}

// ToolDefs returns LLM-compatible tool definitions for all registered tools.
func (r *Registry) ToolDefs() []llm.ToolDef {
	return r.ToolDefsFor(nil)
}

func (r *Registry) ToolDefsFor(categories []string) []llm.ToolDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	defs := make([]llm.ToolDef, 0, len(r.tools))
	for _, t := range r.tools {
		if categories != nil && !slices.Contains(categories, t.Category) {
			continue
		}
		if t.Available != nil && t.Available() != nil {
			continue
		}
		defs = append(defs, llm.ToolDef{
			Type: "function",
			Function: llm.FuncDef{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Function.Name < defs[j].Function.Name })
	return defs
}

func (r *Registry) Availability() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]string)
	for name, tool := range r.tools {
		result[name] = "available"
		if tool.Available != nil {
			if err := tool.Available(); err != nil {
				result[name] = err.Error()
			}
		}
	}
	return result
}

// The built-in schemas use object/string/enum constraints. Validate them here
// instead of relying on the model provider to enforce its advertised schema.
func validateArgs(raw json.RawMessage, schema map[string]any) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return fmt.Errorf("tool arguments must be a JSON object")
	}
	for _, key := range stringValues(schema["required"]) {
		if _, ok := obj[key]; !ok {
			return fmt.Errorf("required argument %q missing", key)
		}
	}
	props, _ := schema["properties"].(map[string]any)
	for key, value := range obj {
		prop, ok := props[key].(map[string]any)
		if !ok {
			return fmt.Errorf("unknown argument %q", key)
		}
		if prop["type"] == "string" {
			var s string
			if string(value) == "null" || json.Unmarshal(value, &s) != nil {
				return fmt.Errorf("argument %q must be a string", key)
			}
			if options := stringValues(prop["enum"]); len(options) > 0 && !slices.Contains(options, s) {
				return fmt.Errorf("invalid value for %q", key)
			}
		}
	}
	return nil
}
func stringValues(v any) []string {
	if ss, ok := v.([]string); ok {
		return ss
	}
	var out []string
	if vs, ok := v.([]any); ok {
		for _, x := range vs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
