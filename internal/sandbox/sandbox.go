// Package sandbox provides bounded code execution for exploit PoCs,
// autonomous CTF solving, and coding-agent sub-shells. All execution
// is gated behind ROGUE_SANDBOX=true and mission scope approval.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Executor runs bounded scripts in an OS-confined environment.
type Executor struct {
	// WorkDir is the temp workspace directory for scripts. Created lazily.
	WorkDir string
	// MaxOutput caps stdout capture in bytes.
	MaxOutput int
	// MaxStderr caps stderr capture in bytes.
	MaxStderr int
	// Timeout is the maximum execution time for a single script.
	Timeout time.Duration
	// AllowNetwork enables outbound network access in scripts (default: false).
	AllowNetwork bool
	// AllowLoopback enables loopback TCP access when AllowNetwork is false
	// (used for scoped local lab PoC verification).
	AllowLoopback bool
	// LoopbackPort, when positive with AllowLoopback, restricts loopback access
	// on Darwin to that single localhost port.
	LoopbackPort int
	// AllowUnconfined permits falling back to host execution when OS
	// confinement is unavailable (default: false; fail closed).
	AllowUnconfined bool

	once    sync.Once
	workErr error
}

// Result holds the output of a script execution.
type Result struct {
	Stdout      string        `json:"stdout"`
	Stderr      string        `json:"stderr"`
	ExitCode    int           `json:"exit_code"`
	Duration    time.Duration `json:"duration_ms"`
	Killed      bool          `json:"killed"`
	Confined    bool          `json:"confined"`
	Confinement string        `json:"confinement,omitempty"`
}

// DefaultExecutor returns an Executor with safe defaults (network disabled,
// filesystem writes confined to WorkDir, fail-closed confinement).
func DefaultExecutor() *Executor {
	return &Executor{
		MaxOutput: 2 * 1024 * 1024,   // 2 MiB
		MaxStderr: 16 * 1024,         // 16 KiB
		Timeout:   120 * time.Second, // 2 minutes
	}
}

// Available checks whether required interpreters are present.
func Available(lang string) error {
	switch strings.ToLower(lang) {
	case "python", "python3":
		if _, err := exec.LookPath("python3"); err != nil {
			return errors.New("python3 is not installed or not in PATH")
		}
		return nil
	case "bash":
		if _, err := exec.LookPath("bash"); err != nil {
			return errors.New("bash is not installed or not in PATH")
		}
		return nil
	case "sh":
		if _, err := exec.LookPath("sh"); err != nil {
			return errors.New("sh is not installed or not in PATH")
		}
		return nil
	default:
		return fmt.Errorf("unsupported language: %s", lang)
	}
}

// DockerAvailable checks if Docker CLI is accessible.
func DockerAvailable() error {
	_, err := exec.LookPath("docker")
	if err != nil {
		return errors.New("docker is not installed or not in PATH")
	}
	return nil
}

func (e *Executor) ensureWorkDir() error {
	e.once.Do(func() {
		if e.WorkDir == "" {
			dir, err := os.MkdirTemp("", "rogue-sandbox-*")
			if err != nil {
				e.workErr = err
				return
			}
			e.WorkDir = dir
		} else {
			if err := os.MkdirAll(e.WorkDir, 0o700); err != nil {
				e.workErr = err
				return
			}
		}
		abs, err := filepath.Abs(e.WorkDir)
		if err != nil {
			e.workErr = err
			return
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		if isUnsafeWorkDir(abs) {
			e.workErr = fmt.Errorf("refusing broad sandbox WorkDir %q", abs)
			return
		}
		e.WorkDir = abs
	})
	return e.workErr
}

func isUnsafeWorkDir(dir string) bool {
	clean := filepath.Clean(dir)
	sysTmp := filepath.Clean(os.TempDir())
	if resolved, err := filepath.EvalSymlinks(sysTmp); err == nil {
		sysTmp = resolved
	}
	switch clean {
	case "/", "/tmp", "/private", "/private/tmp", "/var", "/private/var", "/usr", "/etc", "/Users", "/home", sysTmp:
		return true
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if resolved, err := filepath.EvalSymlinks(home); err == nil {
			home = resolved
		}
		if clean == filepath.Clean(home) {
			return true
		}
	}
	return false
}

// WriteFile writes a file to the sandbox workspace. Only files inside the
// workspace directory are allowed.
func (e *Executor) WriteFile(name, content string) (string, error) {
	if err := e.ensureWorkDir(); err != nil {
		return "", err
	}
	// Sanitize: only basename allowed, no path traversal
	base := filepath.Base(name)
	if base == "." || base == ".." || base != name || strings.ContainsAny(name, "/\\") {
		return "", errors.New("invalid filename: must be a simple basename with no path separators")
	}
	full := filepath.Join(e.WorkDir, base)
	if info, err := os.Lstat(full); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("refusing to write through symlink in sandbox workspace")
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		return "", err
	}
	return full, nil
}

// ExecPython runs a Python3 script in the sandbox.
func (e *Executor) ExecPython(ctx context.Context, script string) (*Result, error) {
	return e.execScript(ctx, "python3", script)
}

// ExecBash runs a bash script in the sandbox.
func (e *Executor) ExecBash(ctx context.Context, script string) (*Result, error) {
	return e.execScript(ctx, "bash", script)
}

func (e *Executor) execScript(ctx context.Context, interpreter, script string) (*Result, error) {
	if err := Available(interpreter); err != nil {
		return nil, err
	}
	if err := e.ensureWorkDir(); err != nil {
		return nil, err
	}
	if len(script) > 256*1024 {
		return nil, errors.New("script exceeds 256 KiB limit")
	}

	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	maxOut := e.MaxOutput
	if maxOut <= 0 {
		maxOut = 2 * 1024 * 1024
	}
	maxErr := e.MaxStderr
	if maxErr <= 0 {
		maxErr = 16 * 1024
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout := &limitedBuf{limit: maxOut, cancel: cancel}
	stderr := &limitedBuf{limit: maxErr, cancel: cancel}

	// Write script to temp file
	scriptFile, err := os.CreateTemp(e.WorkDir, "script-*")
	if err != nil {
		return nil, err
	}
	scriptPath := scriptFile.Name()
	defer os.Remove(scriptPath)
	if _, err := scriptFile.WriteString(script); err != nil {
		scriptFile.Close()
		return nil, err
	}
	scriptFile.Close()

	cmd := exec.CommandContext(execCtx, interpreter, scriptPath)
	cmd.Dir = e.WorkDir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = strings.NewReader("")
	// Minimal safe environment
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=C",
		"LC_ALL=C",
		"HOME=" + e.WorkDir,
		"TMPDIR=" + e.WorkDir,
		"PYTHONDONTWRITEBYTECODE=1",
	}
	cmd.WaitDelay = time.Second

	backend := "unconfined"
	var confineCleanup func()
	if err := ConfinementAvailable(); err == nil {
		cfg := confinementConfig{
			WorkDir:       e.WorkDir,
			AllowNetwork:  e.AllowNetwork,
			AllowLoopback: e.AllowLoopback,
			LoopbackPort:  e.LoopbackPort,
		}
		confined, cleanup, bname, confErr := confineCommand(execCtx, cmd, cfg)
		if confErr != nil {
			return nil, fmt.Errorf("sandbox confinement setup failed: %w", confErr)
		}
		cmd = confined
		confineCleanup = cleanup
		backend = bname
	} else if !e.AllowUnconfined {
		return nil, fmt.Errorf("sandbox confinement unavailable (fail-closed): %w", err)
	}
	if confineCleanup != nil {
		defer confineCleanup()
	}

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	res := &Result{
		Stdout:      stdout.String(),
		Stderr:      stderr.String(),
		Duration:    dur,
		Confined:    backend != "unconfined",
		Confinement: backend,
	}

	if runErr != nil {
		if execCtx.Err() != nil {
			res.Killed = true
			res.ExitCode = -1
		} else if exitErr, ok := runErr.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("sandbox exec failed: %w", runErr)
		}
	}
	return res, nil
}

// Cleanup removes the sandbox workspace directory.
func (e *Executor) Cleanup() error {
	if e.WorkDir != "" {
		return os.RemoveAll(e.WorkDir)
	}
	return nil
}

type limitedBuf struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	limit  int
	cancel context.CancelFunc
}

func (b *limitedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len()+len(p) > b.limit {
		b.cancel()
		return 0, errors.New("output exceeded capture limit")
	}
	return b.buf.Write(p)
}

func (b *limitedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
