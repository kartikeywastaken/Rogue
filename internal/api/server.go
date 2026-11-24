// Package api provides an authenticated HTTP API for the ROGUE harness.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/domain"
	"rogue/internal/engine"
	"rogue/internal/operator"
	"rogue/internal/storage"
	"rogue/internal/telemetry"
)

// Server is the ROGUE HTTP API server.
type Server struct {
	harness  *engine.Harness
	registry *arsenal.Registry
	store    *storage.Store
	apiKey   string
	mux      *http.ServeMux
	streams  sync.Map // mission ID → []chan engine.Event
}

// New creates a wired API server.
func New(harness *engine.Harness, registry *arsenal.Registry, store *storage.Store, apiKey string) *Server {
	s := &Server{harness: harness, registry: registry, store: store, apiKey: apiKey, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/missions", s.requireAuth(s.handleListMissions))
	s.mux.HandleFunc("POST /api/v1/missions", s.requireAuth(s.handleStartMission))
	s.mux.HandleFunc("GET /api/v1/missions/{id}", s.requireAuth(s.handleGetMission))
	s.mux.HandleFunc("DELETE /api/v1/missions/{id}", s.requireAuth(s.handleDeleteMission))
	s.mux.HandleFunc("POST /api/v1/missions/{id}/pause", s.requireAuth(s.handlePauseMission))
	s.mux.HandleFunc("POST /api/v1/missions/{id}/resume", s.requireAuth(s.handleResumeMission))
	s.mux.HandleFunc("POST /api/v1/missions/{id}/abort", s.requireAuth(s.handleAbortMission))
	s.mux.HandleFunc("GET /api/v1/missions/{id}/report", s.requireAuth(s.handleMissionReport))
	s.mux.HandleFunc("GET /api/v1/missions/{id}/events", s.requireAuth(s.handleMissionEvents))
	s.mux.HandleFunc("GET /api/v1/tools", s.requireAuth(s.handleListTools))
	s.mux.HandleFunc("GET /api/v1/tools/{name}", s.requireAuth(s.handleGetTool))
	s.mux.HandleFunc("POST /api/v1/tools/{name}/exec", s.requireAuth(s.handleExecTool))
	s.mux.HandleFunc("GET /api/v1/providers/status", s.requireAuth(s.handleProviderStatus))
	s.mux.HandleFunc("GET /api/v1/operators", s.requireAuth(s.handleListOperators))
	s.mux.HandleFunc("GET /api/v1/config", s.requireAuth(s.handleGetConfig))
}

// Handler returns the HTTP handler with middleware.
func (s *Server) Handler() http.Handler {
	return s.cors(s.limitBody(s.mux))
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe(addr string) error {
	server := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second}
	return server.ListenAndServe()
}

// ── middleware ────────────────────────────────────────────────────────────────

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != s.apiKey {
				writeError(w, http.StatusUnauthorized, "invalid or missing API key")
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Last-Event-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
		next.ServeHTTP(w, r)
	})
}

// ── handlers ─────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "healthy", "version": telemetry.DefaultBuildInfo().Version, "time": time.Now().UTC()})
}

func (s *Server) handleListMissions(w http.ResponseWriter, _ *http.Request) {
	if s.store == nil {
		writeError(w, http.StatusServiceUnavailable, "storage not configured")
		return
	}
	missions, err := s.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, missions)
}

func (s *Server) handleGetMission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	report, err := s.harness.Report(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleDeleteMission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.store == nil {
		writeError(w, http.StatusServiceUnavailable, "storage not configured")
		return
	}
	if _, err := s.store.Load(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleStartMission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Prompt string `json:"prompt"`
		Mode   string `json:"mode"`
		Model  string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Prompt == "" {
		writeError(w, http.StatusBadRequest, "prompt is required")
		return
	}
	mode := engine.ModeAuto
	switch body.Mode {
	case "default":
		mode = engine.ModeDefault
	case "plan":
		mode = engine.ModePlan
	case "auto", "":
		mode = engine.ModeAuto
	default:
		writeError(w, http.StatusBadRequest, "mode must be default, auto, or plan")
		return
	}
	request := engine.Request{Prompt: body.Prompt, Mode: mode, Model: body.Model}
	missionID := domain.ID()
	go func() {
		ctx := context.Background()
		for range s.harness.Run(ctx, request) {
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"mission_id": missionID, "status": "started"})
}

func (s *Server) handlePauseMission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.harness.PauseMission(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"paused": id})
}

func (s *Server) handleResumeMission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.harness.ResumeMission(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resumed": id})
}

func (s *Server) handleAbortMission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct{ Reason string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Reason == "" {
		body.Reason = "aborted via API"
	}
	if err := s.harness.AbortMission(id, body.Reason); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aborted": id})
}

func (s *Server) handleMissionReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	report, err := s.harness.Report(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	format := r.URL.Query().Get("format")
	if format == "markdown" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, report.Markdown())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleMissionEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	id := r.PathValue("id")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	// Try to get a report for context
	report, err := s.harness.Report(id)
	if err != nil {
		fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
		flusher.Flush()
		return
	}
	data, _ := json.Marshal(map[string]any{"mission_id": id, "status": report.Mission.Status, "tasks": len(report.Mission.Tasks), "findings": report.Analysis.FindingsWithEvidence})
	fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", data)
	flusher.Flush()
	// Keep alive until client disconnects
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleListTools(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.registry.Catalog())
}

func (s *Server) handleGetTool(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	tool := s.registry.Get(name)
	if tool == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown tool %q", name))
		return
	}
	status := "available"
	if tool.Available != nil {
		if err := tool.Available(); err != nil {
			status = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": tool.Name, "category": tool.Category, "description": tool.Description, "parameters": tool.Parameters, "availability": status, "lab_only": tool.LabOnly, "internal": tool.Internal})
}

func (s *Server) handleExecTool(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		Arguments json.RawMessage `json:"arguments"`
		Role      string          `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Arguments == nil {
		body.Arguments = json.RawMessage("{}")
	}
	if body.Role == "" {
		body.Role = "scanner"
	}
	report, err := s.harness.ExecuteTool(r.Context(), name, body.Arguments, domain.Archetype(body.Role), engine.ModeAuto)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleProviderStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"models": s.harness.Models(), "config": telemetry.SummarizeConfig()})
}

func (s *Server) handleListOperators(w http.ResponseWriter, _ *http.Request) {
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
	writeJSON(w, http.StatusOK, profiles)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, telemetry.SummarizeConfig())
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message, "status": status})
}
