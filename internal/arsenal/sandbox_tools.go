package arsenal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"rogue/internal/sandbox"
)

// RegisterSandboxTools registers code execution tools for exploit PoCs
// and autonomous CTF solving. All tools require ROGUE_SANDBOX=true.
func RegisterSandboxTools(registry *Registry) {
	exec := sandbox.DefaultExecutor()

	registry.Register(pythonExecTool(exec))
	registry.Register(bashExecTool(exec))
	registry.Register(scriptWriteTool(exec))
}

func sandboxEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ROGUE_SANDBOX")))
	return v == "true" || v == "1"
}

func pythonExecTool(exec *sandbox.Executor) *Tool {
	return &Tool{
		Name:     "python_exec",
		Category: "exploit",
		Description: "Execute a bounded Python3 script in the sandbox. " +
			"Used for exploit PoC verification, CTF solving, and security analysis. " +
			"Requires ROGUE_SANDBOX=true and mission scope approval. " +
			"Scripts are time-limited (120s) and output-capped (2 MiB).",
		Available: func() error {
			if !sandboxEnabled() {
				return errors.New("ROGUE_SANDBOX=true required for code execution")
			}
			return sandbox.Available("python3")
		},
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"script":  map[string]any{"type": "string", "description": "Python3 script source code to execute"},
			"purpose": map[string]any{"type": "string", "description": "Brief description of what this script does (for audit trail)"},
		}, "required": []string{"script", "purpose"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			if !sandboxEnabled() {
				return nil, errors.New("ROGUE_SANDBOX=true required for code execution")
			}
			var args struct {
				Script  string `json:"script"`
				Purpose string `json:"purpose"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Script == "" {
				return nil, errors.New("script is required")
			}
			if args.Purpose == "" {
				return nil, errors.New("purpose description is required for audit trail")
			}
			if err := authorizeActive(ctx, "python_exec", raw); err != nil {
				return nil, err
			}

			res, err := exec.ExecPython(ctx, args.Script)
			if err != nil {
				return nil, fmt.Errorf("python execution failed: %w", err)
			}

			data := map[string]any{
				"exit_code": res.ExitCode,
				"stdout":    clipOutput(res.Stdout, 32768),
				"stderr":    clipOutput(res.Stderr, 4096),
				"duration":  res.Duration.String(),
				"killed":    res.Killed,
				"purpose":   args.Purpose,
			}

			summary := fmt.Sprintf("Python script executed (exit %d, %s)", res.ExitCode, res.Duration.Round(time.Millisecond))
			if res.Killed {
				summary = "Python script killed (timeout exceeded)"
			}

			return &Result{Success: res.ExitCode == 0, Data: data, Summary: summary}, nil
		},
	}
}

func bashExecTool(exec *sandbox.Executor) *Tool {
	return &Tool{
		Name:     "bash_exec",
		Category: "exploit",
		Description: "Execute a bounded bash script in the sandbox. " +
			"Used for exploit PoC verification, CTF solving, and system analysis. " +
			"Requires ROGUE_SANDBOX=true and mission scope approval. " +
			"Scripts are time-limited (120s) and output-capped (2 MiB).",
		Available: func() error {
			if !sandboxEnabled() {
				return errors.New("ROGUE_SANDBOX=true required for code execution")
			}
			return sandbox.Available("bash")
		},
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"script":  map[string]any{"type": "string", "description": "Bash script source code to execute"},
			"purpose": map[string]any{"type": "string", "description": "Brief description of what this script does (for audit trail)"},
		}, "required": []string{"script", "purpose"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			if !sandboxEnabled() {
				return nil, errors.New("ROGUE_SANDBOX=true required for code execution")
			}
			var args struct {
				Script  string `json:"script"`
				Purpose string `json:"purpose"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Script == "" {
				return nil, errors.New("script is required")
			}
			if args.Purpose == "" {
				return nil, errors.New("purpose description is required for audit trail")
			}
			if err := authorizeActive(ctx, "bash_exec", raw); err != nil {
				return nil, err
			}

			res, err := exec.ExecBash(ctx, args.Script)
			if err != nil {
				return nil, fmt.Errorf("bash execution failed: %w", err)
			}

			data := map[string]any{
				"exit_code": res.ExitCode,
				"stdout":    clipOutput(res.Stdout, 32768),
				"stderr":    clipOutput(res.Stderr, 4096),
				"duration":  res.Duration.String(),
				"killed":    res.Killed,
				"purpose":   args.Purpose,
			}

			summary := fmt.Sprintf("Bash script executed (exit %d, %s)", res.ExitCode, res.Duration.Round(time.Millisecond))
			if res.Killed {
				summary = "Bash script killed (timeout exceeded)"
			}

			return &Result{Success: res.ExitCode == 0, Data: data, Summary: summary}, nil
		},
	}
}

func scriptWriteTool(exec *sandbox.Executor) *Tool {
	return &Tool{
		Name:     "script_write",
		Category: "exploit",
		Description: "Write a file to the sandbox workspace directory. " +
			"Only simple filenames are allowed (no path traversal). " +
			"Used for creating exploit payloads, helper scripts, and data files. " +
			"Requires ROGUE_SANDBOX=true.",
		Available: func() error {
			if !sandboxEnabled() {
				return errors.New("ROGUE_SANDBOX=true required")
			}
			return nil
		},
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"filename": map[string]any{"type": "string", "description": "Simple filename (no directories or path traversal)"},
			"content":  map[string]any{"type": "string", "description": "File content to write"},
		}, "required": []string{"filename", "content"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			if !sandboxEnabled() {
				return nil, errors.New("ROGUE_SANDBOX=true required")
			}
			var args struct {
				Filename string `json:"filename"`
				Content  string `json:"content"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Filename == "" {
				return nil, errors.New("filename is required")
			}
			if len(args.Content) > 1024*1024 {
				return nil, errors.New("file content exceeds 1 MiB limit")
			}

			path, err := exec.WriteFile(args.Filename, args.Content)
			if err != nil {
				return nil, err
			}

			return &Result{
				Success: true,
				Data:    map[string]any{"path": path, "size": len(args.Content)},
				Summary: fmt.Sprintf("File %q written to sandbox (%d bytes)", args.Filename, len(args.Content)),
			}, nil
		},
	}
}

func clipOutput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (truncated)"
}
