// Package arsenal provides the tool registry and execution layer. Tools are
// registered with typed parameter schemas and execute real operations.
package arsenal

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"rogue/internal/llm"
)

// ── tool interface ───────────────────────────────────────────────────────────

// Tool is a single executable capability.
type Tool struct {
	Name        string
	Category    string // recon, web, vuln, auth, util
	Description string
	Parameters  map[string]any // JSON Schema for the LLM
	Execute     func(ctx context.Context, args json.RawMessage) (*Result, error)
}

// Result is the output of a tool execution.
type Result struct {
	Success bool
	Data    any
	Summary string        // short human-readable summary
	Dur     time.Duration // wall time
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
	start := time.Now()
	res, err := t.Execute(ctx, args)
	if err != nil {
		return &Result{Success: false, Summary: err.Error(), Dur: time.Since(start)}, err
	}
	res.Dur = time.Since(start)
	return res, nil
}

// ToolDefs returns LLM-compatible tool definitions for all registered tools.
func (r *Registry) ToolDefs() []llm.ToolDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	defs := make([]llm.ToolDef, 0, len(r.tools))
	for _, t := range r.tools {
		defs = append(defs, llm.ToolDef{
			Type: "function",
			Function: llm.FuncDef{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}
	return defs
}
