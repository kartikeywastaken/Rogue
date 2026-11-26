package arsenal

// whitebox_tool.go — registers the whitebox_analyze tool.

import (
	"context"
	"encoding/json"
	"fmt"

	"rogue/internal/whitebox"
)

// RegisterWhiteboxTool adds the whitebox_analyze tool to the registry.
func RegisterWhiteboxTool(registry *Registry) {
	registry.Register(&Tool{
		Name:        "whitebox_analyze",
		Category:    "util",
		Description: "Static white-box analysis of a local repository: dependency decomposition, redacted secret detection, and SAST patterns. Read-only; never executes code.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"repo_path": map[string]any{"type": "string", "description": "absolute path to the repository root"},
		}, "required": []string{"repo_path"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				RepoPath string `json:"repo_path"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if a.RepoPath == "" {
				return fail(fmt.Errorf("whitebox_analyze: repo_path is required"))
			}
			report, err := whitebox.Analyze(ctx, a.RepoPath)
			if err != nil {
				return fail(err)
			}
			summary := fmt.Sprintf("Scanned %d files: %d secrets, %d SAST findings, %d dependencies",
				report.FilesScanned, len(report.Secrets), len(report.SASTFindings), len(report.Dependencies))
			return &Result{Success: true, Summary: summary, Data: report}, nil
		},
	})
}
