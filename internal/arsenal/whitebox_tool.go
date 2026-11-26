package arsenal

// whitebox_tool.go — registers the whitebox_analyze tool.

import (
	"context"
	"encoding/json"

	"rogue/internal/whitebox"
)

// RegisterWhiteboxTool adds the whitebox_analyze tool to the registry.
func RegisterWhiteboxTool(registry *Registry) {
	registry.Register(&Tool{
		Name:        "whitebox_analyze",
		Category:    "util",
		Description: "Static white-box analysis of a local repository: secret detection and SAST patterns. Read-only. Never executes code.",
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
			return ok(report), nil
		},
	})
}
