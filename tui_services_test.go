package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rogue/internal/arsenal"
	"rogue/internal/domain"
	"rogue/internal/engine"
	"rogue/internal/mission"
	"rogue/internal/storage"
)

func TestTUIExportsUseSavedReportAndDoNotReplaceFiles(t *testing.T) {
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := arsenal.New()
	reg.Register(&arsenal.Tool{Name: "local_fixture", Category: "recon", Parameters: map[string]any{"type": "object", "properties": map[string]any{}}, Execute: func(context.Context, json.RawMessage) (*arsenal.Result, error) {
		return &arsenal.Result{Success: true, Summary: "Local fixture observation"}, nil
	}})
	h := engine.NewHarnessWithOptions(nil, reg, nil, "", engine.Options{Store: store, Rules: mission.Rules{Scope: []string{"127.0.0.1"}}})
	report, err := h.ExecuteTool(context.Background(), "local_fixture", json.RawMessage(`{}`), domain.ArchRecon, engine.ModeDefault)
	if err != nil {
		t.Fatal(err)
	}
	svc := tuiWarRoomServices()
	dir := t.TempDir()
	for _, format := range []string{"json", "sarif", "html", "markdown", "pdf"} {
		path := filepath.Join(dir, "report."+format)
		saved, err := svc.Export(h, report.Mission.ID, format, path)
		if err != nil {
			t.Fatal(format, err)
		}
		if saved != path {
			t.Fatal("wrong destination", saved)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			t.Fatal("empty export", format)
		}
		if format == "pdf" && !strings.HasPrefix(string(data), "%PDF-1.4") {
			t.Fatal("invalid PDF export")
		}
		if format == "json" && !json.Valid(data) {
			t.Fatal("invalid JSON export")
		}
		if _, err = svc.Export(h, report.Mission.ID, format, path); err == nil {
			t.Fatal("export overwrote an existing destination", format)
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(data) {
			t.Fatal("existing file changed")
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("report is not private", info.Mode())
		}
	}
}
