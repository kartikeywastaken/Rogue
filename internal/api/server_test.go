package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"rogue/internal/arsenal"
	"rogue/internal/engine"
	"rogue/internal/storage"
	"rogue/internal/whitebox"
)

func TestWhiteboxAnalyzeRouteAndAuth(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.py"), []byte(`eval(input("x"))`), 0600)

	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := engine.NewHarnessWithOptions(nil, arsenal.New(), nil, "", engine.Options{Store: store})
	srv := New(h, arsenal.New(), store, "secret-token")

	// Unauthorized
	body, _ := json.Marshal(map[string]string{"repo_path": dir})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whitebox/analyze", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	// Authorized
	req = httptest.NewRequest(http.MethodPost, "/api/v1/whitebox/analyze", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-token")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var rep whitebox.Report
	if err := json.NewDecoder(rec.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.FilesScanned != 1 || len(rep.SASTFindings) == 0 {
		t.Fatalf("unexpected whitebox report: %+v", rep)
	}

	// Inspect non-existent mission -> 404
	req = httptest.NewRequest(http.MethodGet, "/api/v1/missions/nonexistent/inspect", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent inspect, got %d", rec.Code)
	}
}
