// Package telemetry provides structured operational logging, metrics collection,
// and runtime diagnostics for the ROGUE harness. It does not phone home; all
// data stays local unless explicitly exported.
package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// ── metrics ──────────────────────────────────────────────────────────────────

// Counter is a monotonically increasing metric.
type Counter struct {
	mu    sync.Mutex
	name  string
	value int64
}

func NewCounter(name string) *Counter { return &Counter{name: name} }
func (c *Counter) Inc()               { c.mu.Lock(); c.value++; c.mu.Unlock() }
func (c *Counter) Add(delta int64)    { c.mu.Lock(); c.value += delta; c.mu.Unlock() }
func (c *Counter) Value() int64       { c.mu.Lock(); defer c.mu.Unlock(); return c.value }

// Gauge is a point-in-time metric.
type Gauge struct {
	mu    sync.Mutex
	name  string
	value float64
}

func NewGauge(name string) *Gauge          { return &Gauge{name: name} }
func (g *Gauge) Set(value float64)         { g.mu.Lock(); g.value = value; g.mu.Unlock() }
func (g *Gauge) Value() float64            { g.mu.Lock(); defer g.mu.Unlock(); return g.value }

// Histogram records value distributions.
type Histogram struct {
	mu     sync.Mutex
	name   string
	values []float64
	sum    float64
	count  int64
}

func NewHistogram(name string) *Histogram { return &Histogram{name: name} }

func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	h.values = append(h.values, value)
	h.sum += value
	h.count++
	// Keep at most 10000 samples
	if len(h.values) > 10000 {
		h.values = h.values[len(h.values)-10000:]
	}
	h.mu.Unlock()
}

func (h *Histogram) Summary() HistogramSummary {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return HistogramSummary{Name: h.name}
	}
	sorted := make([]float64, len(h.values))
	copy(sorted, h.values)
	sort.Float64s(sorted)
	return HistogramSummary{
		Name:  h.name,
		Count: h.count,
		Sum:   h.sum,
		Mean:  h.sum / float64(h.count),
		Min:   sorted[0],
		Max:   sorted[len(sorted)-1],
		P50:   percentile(sorted, 0.5),
		P95:   percentile(sorted, 0.95),
		P99:   percentile(sorted, 0.99),
	}
}

type HistogramSummary struct {
	Name  string  `json:"name"`
	Count int64   `json:"count"`
	Sum   float64 `json:"sum"`
	Mean  float64 `json:"mean"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1) * p)
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

// ── collector ────────────────────────────────────────────────────────────────

// Collector aggregates metrics from all harness components.
type Collector struct {
	mu         sync.RWMutex
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	startedAt  time.Time
}

func NewCollector() *Collector {
	return &Collector{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
		startedAt:  time.Now(),
	}
}

func (c *Collector) Counter(name string) *Counter {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.counters[name]; !exists {
		c.counters[name] = NewCounter(name)
	}
	return c.counters[name]
}

func (c *Collector) Gauge(name string) *Gauge {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.gauges[name]; !exists {
		c.gauges[name] = NewGauge(name)
	}
	return c.gauges[name]
}

func (c *Collector) Histogram(name string) *Histogram {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.histograms[name]; !exists {
		c.histograms[name] = NewHistogram(name)
	}
	return c.histograms[name]
}

// MetricsSnapshot returns a point-in-time snapshot of all collected metrics.
type MetricsSnapshot struct {
	Timestamp  time.Time                    `json:"timestamp"`
	Uptime     string                       `json:"uptime"`
	Counters   map[string]int64             `json:"counters"`
	Gauges     map[string]float64           `json:"gauges"`
	Histograms map[string]HistogramSummary  `json:"histograms"`
	Runtime    RuntimeInfo                  `json:"runtime"`
}

type RuntimeInfo struct {
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"num_goroutine"`
	NumCPU       int    `json:"num_cpu"`
	MemAllocMB   float64 `json:"mem_alloc_mb"`
	MemSysMB     float64 `json:"mem_sys_mb"`
	GCPauseMS    float64 `json:"gc_pause_ms"`
}

func (c *Collector) Snapshot() MetricsSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := MetricsSnapshot{
		Timestamp:  time.Now().UTC(),
		Uptime:     time.Since(c.startedAt).Round(time.Second).String(),
		Counters:   make(map[string]int64),
		Gauges:     make(map[string]float64),
		Histograms: make(map[string]HistogramSummary),
	}
	for name, counter := range c.counters {
		snapshot.Counters[name] = counter.Value()
	}
	for name, gauge := range c.gauges {
		snapshot.Gauges[name] = gauge.Value()
	}
	for name, histogram := range c.histograms {
		snapshot.Histograms[name] = histogram.Summary()
	}
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	snapshot.Runtime = RuntimeInfo{
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		NumCPU:       runtime.NumCPU(),
		MemAllocMB:   float64(memStats.Alloc) / 1024 / 1024,
		MemSysMB:     float64(memStats.Sys) / 1024 / 1024,
		GCPauseMS:    float64(memStats.PauseTotalNs) / 1e6,
	}
	return snapshot
}

// ── structured logger ────────────────────────────────────────────────────────

// Level controls log verbosity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// LogEntry is a structured log line.
type LogEntry struct {
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"`
	Message string         `json:"msg"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// Logger writes structured JSON logs.
type Logger struct {
	mu       sync.Mutex
	encoder  *json.Encoder
	level    Level
	fields   map[string]any
	file     *os.File
}

func NewLogger(level Level) *Logger {
	return &Logger{
		encoder: json.NewEncoder(os.Stderr),
		level:   level,
		fields:  make(map[string]any),
	}
}

func NewFileLogger(path string, level Level) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &Logger{
		encoder: json.NewEncoder(file),
		level:   level,
		fields:  make(map[string]any),
		file:    file,
	}, nil
}

func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) With(key string, value any) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	newFields := make(map[string]any, len(l.fields)+1)
	for k, v := range l.fields {
		newFields[k] = v
	}
	newFields[key] = value
	return &Logger{encoder: l.encoder, level: l.level, fields: newFields, file: l.file}
}

func (l *Logger) log(level Level, msg string, fields map[string]any) {
	if level < l.level {
		return
	}
	entry := LogEntry{
		Time:    time.Now().UTC(),
		Level:   level.String(),
		Message: msg,
	}
	if len(l.fields) > 0 || len(fields) > 0 {
		merged := make(map[string]any, len(l.fields)+len(fields))
		for k, v := range l.fields {
			merged[k] = v
		}
		for k, v := range fields {
			merged[k] = v
		}
		entry.Fields = merged
	}
	l.mu.Lock()
	_ = l.encoder.Encode(entry)
	l.mu.Unlock()
}

func (l *Logger) Debug(msg string, fields ...map[string]any) {
	l.log(LevelDebug, msg, mergeFields(fields))
}
func (l *Logger) Info(msg string, fields ...map[string]any) {
	l.log(LevelInfo, msg, mergeFields(fields))
}
func (l *Logger) Warn(msg string, fields ...map[string]any) {
	l.log(LevelWarn, msg, mergeFields(fields))
}
func (l *Logger) Error(msg string, fields ...map[string]any) {
	l.log(LevelError, msg, mergeFields(fields))
}

func mergeFields(fields []map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	result := make(map[string]any)
	for _, f := range fields {
		for k, v := range f {
			result[k] = v
		}
	}
	return result
}

// ── health check ─────────────────────────────────────────────────────────────

// HealthStatus represents the operational state of a component.
type HealthStatus struct {
	Status    string            `json:"status"` // "healthy", "degraded", "unhealthy"
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	Checks    map[string]Check  `json:"checks"`
	StartedAt time.Time         `json:"started_at"`
}

type Check struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Latency string `json:"latency,omitempty"`
}

type HealthChecker struct {
	version   string
	startedAt time.Time
	checks    map[string]func() Check
	mu        sync.RWMutex
}

func NewHealthChecker(version string) *HealthChecker {
	return &HealthChecker{
		version:   version,
		startedAt: time.Now(),
		checks:    make(map[string]func() Check),
	}
}

func (hc *HealthChecker) Register(name string, check func() Check) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.checks[name] = check
}

func (hc *HealthChecker) Status() HealthStatus {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	status := HealthStatus{
		Status:    "healthy",
		Version:   hc.version,
		Uptime:    time.Since(hc.startedAt).Round(time.Second).String(),
		StartedAt: hc.startedAt,
		Checks:    make(map[string]Check),
	}
	for name, check := range hc.checks {
		result := check()
		status.Checks[name] = result
		if result.Status == "unhealthy" {
			status.Status = "unhealthy"
		} else if result.Status == "degraded" && status.Status == "healthy" {
			status.Status = "degraded"
		}
	}
	return status
}

// ── retention policy ─────────────────────────────────────────────────────────

type RetentionPolicy struct {
	MaxAgeDays     int  `json:"max_age_days"`
	MaxCount       int  `json:"max_count"`
	KeepFailed     bool `json:"keep_failed"`
	KeepWithFindings bool `json:"keep_with_findings"`
}

func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		MaxAgeDays:       30,
		MaxCount:         100,
		KeepFailed:       true,
		KeepWithFindings: true,
	}
}

// ── build info ───────────────────────────────────────────────────────────────

// BuildInfo is populated at build time via ldflags.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func DefaultBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   "dev",
		Commit:    "unknown",
		BuildDate: "unknown",
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// ── configuration summary ────────────────────────────────────────────────────

type ConfigSummary struct {
	Provider       string            `json:"provider"`
	Model          string            `json:"model"`
	Models         []string          `json:"models"`
	Lab            bool              `json:"lab"`
	Scope          []string          `json:"scope"`
	Timeout        string            `json:"timeout"`
	MaxIterations  int               `json:"max_iterations"`
	MaxToolCalls   int               `json:"max_tool_calls"`
	MaxTokens      int               `json:"max_tokens"`
	Concurrency    int               `json:"concurrency"`
	StateDir       string            `json:"state_dir"`
	ToolCount      int               `json:"tool_count"`
	Environment    map[string]string `json:"environment"`
}

func SummarizeConfig() ConfigSummary {
	env := make(map[string]string)
	for _, key := range []string{
		"ROGUE_PROVIDER", "ROGUE_MODEL", "ROGUE_SCOPE", "ROGUE_LAB",
		"ROGUE_TIMEOUT", "ROGUE_MAX_ITERATIONS", "ROGUE_MAX_TOOL_CALLS",
		"ROGUE_MAX_TOKENS", "ROGUE_CONCURRENCY", "ROGUE_STATE_DIR",
		"ROGUE_CONTEXT_BYTES", "ROGUE_COOLDOWN",
	} {
		if value := os.Getenv(key); value != "" {
			env[key] = value
		}
	}
	// Redact secrets
	for _, key := range []string{
		"OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
		"GROQ_API_KEY", "NVD_API_KEY", "ROGUE_API_KEY",
	} {
		if value := os.Getenv(key); value != "" {
			if len(value) > 8 {
				env[key] = value[:4] + "..." + value[len(value)-4:]
			} else {
				env[key] = "***"
			}
		}
	}
	return ConfigSummary{
		Provider:    os.Getenv("ROGUE_PROVIDER"),
		Model:       os.Getenv("ROGUE_MODEL"),
		Lab:         os.Getenv("ROGUE_LAB") == "true",
		StateDir:    os.Getenv("ROGUE_STATE_DIR"),
		Environment: env,
	}
}
