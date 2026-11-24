// Package plugin provides tool extension contracts, lifecycle hooks, and a
// file-backed knowledge base for the ROGUE harness.
package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── manifest & spec ──────────────────────────────────────────────────────────

// Manifest describes a plugin loaded from a directory.
type Manifest struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Author      string     `json:"author,omitempty"`
	Tools       []ToolSpec `json:"tools,omitempty"`
	Hooks       []string   `json:"hooks,omitempty"`
	MinVersion  string     `json:"min_version,omitempty"`
}

// ToolSpec describes a tool contributed by a plugin.
type ToolSpec struct {
	Name        string         `json:"name"`
	Category    string         `json:"category"`
	Description string         `json:"description"`
	Command     string         `json:"command"`
	Args        []string       `json:"args,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	LabOnly     bool           `json:"lab_only,omitempty"`
	Timeout     string         `json:"timeout,omitempty"`
}

// ── plugin ───────────────────────────────────────────────────────────────────

// Plugin is a loaded, optionally enabled extension.
type Plugin struct {
	Manifest Manifest  `json:"manifest"`
	Dir      string    `json:"dir"`
	Enabled  bool      `json:"enabled"`
	LoadedAt time.Time `json:"loaded_at"`
	Error    string    `json:"error,omitempty"`
}

// ── hook system ──────────────────────────────────────────────────────────────

// HookEvent identifies when a hook fires.
type HookEvent string

const (
	HookMissionStart    HookEvent = "mission.start"
	HookMissionComplete HookEvent = "mission.complete"
	HookMissionAbort    HookEvent = "mission.abort"
	HookToolBefore      HookEvent = "tool.before"
	HookToolAfter       HookEvent = "tool.after"
	HookFindingCreated  HookEvent = "finding.created"
	HookReportExport    HookEvent = "report.export"
)

// HookFunc is a callback invoked when an event fires.
type HookFunc func(event HookEvent, data map[string]any) error

// ── registry ─────────────────────────────────────────────────────────────────

// Registry manages plugin lifecycle and hooks.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*Plugin
	hooks   map[HookEvent][]hookEntry
}

type hookEntry struct {
	plugin string
	fn     HookFunc
}

func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]*Plugin),
		hooks:   make(map[HookEvent][]hookEntry),
	}
}

// Load reads a plugin manifest from a directory.
func (r *Registry) Load(dir string) (*Plugin, error) {
	manifestPath := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("plugin: reading manifest from %s: %w", dir, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("plugin: parsing manifest in %s: %w", dir, err)
	}
	if m.Name == "" {
		return nil, fmt.Errorf("plugin: manifest in %s missing name", dir)
	}
	if m.Version == "" {
		m.Version = "0.0.0"
	}
	p := &Plugin{Manifest: m, Dir: dir, Enabled: true, LoadedAt: time.Now().UTC()}
	r.mu.Lock()
	r.plugins[m.Name] = p
	r.mu.Unlock()
	return p, nil
}

// Register adds a pre-constructed plugin (useful for built-in extensions).
func (r *Registry) Register(p *Plugin) error {
	if p.Manifest.Name == "" {
		return errors.New("plugin: name required")
	}
	r.mu.Lock()
	r.plugins[p.Manifest.Name] = p
	r.mu.Unlock()
	return nil
}

// Get returns a plugin by name.
func (r *Registry) Get(name string) *Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.plugins[name]
}

// All returns all loaded plugins.
func (r *Registry) All() []*Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Manifest.Name < result[j].Manifest.Name })
	return result
}

// Enable turns a plugin on.
func (r *Registry) Enable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.plugins[name]
	if !ok {
		return fmt.Errorf("plugin %q not found", name)
	}
	p.Enabled = true
	return nil
}

// Disable turns a plugin off without unloading it.
func (r *Registry) Disable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.plugins[name]
	if !ok {
		return fmt.Errorf("plugin %q not found", name)
	}
	p.Enabled = false
	return nil
}

// RegisterHook attaches a callback to a hook event for a named plugin.
func (r *Registry) RegisterHook(plugin string, event HookEvent, fn HookFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks[event] = append(r.hooks[event], hookEntry{plugin: plugin, fn: fn})
}

// FireHook invokes all enabled hooks for an event. Errors are collected.
func (r *Registry) FireHook(event HookEvent, data map[string]any) error {
	r.mu.RLock()
	entries := append([]hookEntry{}, r.hooks[event]...)
	r.mu.RUnlock()

	var errs []error
	for _, entry := range entries {
		p := r.Get(entry.plugin)
		if p != nil && !p.Enabled {
			continue
		}
		if err := entry.fn(event, data); err != nil {
			errs = append(errs, fmt.Errorf("hook %s/%s: %w", entry.plugin, event, err))
		}
	}
	return errors.Join(errs...)
}

// ── knowledge base ───────────────────────────────────────────────────────────

// KnowledgeEntry is a single item in the knowledge base.
type KnowledgeEntry struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Content  string    `json:"content"`
	Tags     []string  `json:"tags,omitempty"`
	Source   string    `json:"source,omitempty"`
	AddedAt  time.Time `json:"added_at"`
}

// KnowledgeBase is a file-backed searchable knowledge store.
type KnowledgeBase struct {
	mu      sync.RWMutex
	entries []KnowledgeEntry
	path    string
}

func NewKnowledgeBase(path string) *KnowledgeBase {
	return &KnowledgeBase{path: path}
}

// Load reads entries from the backing file. If the file doesn't exist, starts empty.
func (kb *KnowledgeBase) Load() error {
	data, err := os.ReadFile(kb.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	kb.mu.Lock()
	defer kb.mu.Unlock()
	return json.Unmarshal(data, &kb.entries)
}

// Save persists entries to the backing file.
func (kb *KnowledgeBase) Save() error {
	kb.mu.RLock()
	data, err := json.MarshalIndent(kb.entries, "", "  ")
	kb.mu.RUnlock()
	if err != nil {
		return err
	}
	dir := filepath.Dir(kb.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(kb.path, data, 0600)
}

// Add inserts a new entry and persists.
func (kb *KnowledgeBase) Add(entry KnowledgeEntry) error {
	if entry.Title == "" {
		return errors.New("knowledge entry requires a title")
	}
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("kb-%d", time.Now().UnixNano())
	}
	if entry.AddedAt.IsZero() {
		entry.AddedAt = time.Now().UTC()
	}
	kb.mu.Lock()
	kb.entries = append(kb.entries, entry)
	kb.mu.Unlock()
	return kb.Save()
}

// Get retrieves an entry by ID.
func (kb *KnowledgeBase) Get(id string) (KnowledgeEntry, bool) {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	for _, e := range kb.entries {
		if e.ID == id {
			return e, true
		}
	}
	return KnowledgeEntry{}, false
}

// Search returns entries whose title, content, or tags match the query (case-insensitive).
func (kb *KnowledgeBase) Search(query string) []KnowledgeEntry {
	query = strings.ToLower(query)
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	var results []KnowledgeEntry
	for _, e := range kb.entries {
		if strings.Contains(strings.ToLower(e.Title), query) ||
			strings.Contains(strings.ToLower(e.Content), query) {
			results = append(results, e)
			continue
		}
		for _, tag := range e.Tags {
			if strings.Contains(strings.ToLower(tag), query) {
				results = append(results, e)
				break
			}
		}
	}
	return results
}

// Count returns the total number of entries.
func (kb *KnowledgeBase) Count() int {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	return len(kb.entries)
}

// All returns all entries.
func (kb *KnowledgeBase) All() []KnowledgeEntry {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	result := make([]KnowledgeEntry, len(kb.entries))
	copy(result, kb.entries)
	return result
}
