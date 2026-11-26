package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecPython(t *testing.T) {
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	res, err := exec.ExecPython(context.Background(), `print("hello from sandbox")`)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "hello from sandbox") {
		t.Fatalf("expected output, got %q", res.Stdout)
	}
	if res.Duration <= 0 {
		t.Fatal("expected positive duration")
	}
}

func TestExecBash(t *testing.T) {
	if err := Available("bash"); err != nil {
		t.Skip("bash not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	res, err := exec.ExecBash(context.Background(), `echo "bash works" && echo "line 2"`)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d", res.ExitCode)
	}
	if !strings.Contains(res.Stdout, "bash works") {
		t.Fatalf("unexpected output: %q", res.Stdout)
	}
}

func TestExecTimeout(t *testing.T) {
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	exec := DefaultExecutor()
	exec.Timeout = 1 * time.Second
	defer exec.Cleanup()

	res, err := exec.ExecPython(context.Background(), `import time; time.sleep(30)`)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Killed {
		t.Fatal("expected script to be killed on timeout")
	}
}

func TestExecExitCode(t *testing.T) {
	if err := Available("bash"); err != nil {
		t.Skip("bash not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	res, err := exec.ExecBash(context.Background(), `exit 42`)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 42 {
		t.Fatalf("expected exit 42, got %d", res.ExitCode)
	}
}

func TestExecStderr(t *testing.T) {
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	res, err := exec.ExecPython(context.Background(), `import sys; sys.stderr.write("warning\n"); print("ok")`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stderr, "warning") {
		t.Fatalf("expected stderr warning, got %q", res.Stderr)
	}
	if !strings.Contains(res.Stdout, "ok") {
		t.Fatalf("expected stdout ok, got %q", res.Stdout)
	}
}

func TestWriteFile(t *testing.T) {
	exec := DefaultExecutor()
	defer exec.Cleanup()

	path, err := exec.WriteFile("test.txt", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "test.txt") {
		t.Fatalf("unexpected path: %s", path)
	}

	// Path traversal must fail
	_, err = exec.WriteFile("../escape.txt", "bad")
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	_, err = exec.WriteFile("../../etc/passwd", "bad")
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
}

func TestScriptSizeLimit(t *testing.T) {
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	bigScript := strings.Repeat("x", 257*1024)
	_, err := exec.ExecPython(context.Background(), bigScript)
	if err == nil {
		t.Fatal("expected error for oversized script")
	}
}

func TestAvailable(t *testing.T) {
	// Should always succeed on dev machines
	for _, lang := range []string{"bash", "sh"} {
		if err := Available(lang); err != nil {
			t.Logf("%s not available (ok on some systems): %v", lang, err)
		}
	}
	// Invalid language
	if err := Available("cobol"); err == nil {
		t.Fatal("expected error for unsupported language")
	}
}

func TestDockerAvailable(t *testing.T) {
	err := DockerAvailable()
	if err != nil {
		t.Logf("Docker not available (expected in CI): %v", err)
	}
}

func TestEnvStripping(t *testing.T) {
	if err := Available("bash"); err != nil {
		t.Skip("bash not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	// API keys from the host env should not leak into sandbox scripts
	res, err := exec.ExecBash(context.Background(), `echo "KEY=$OPENAI_API_KEY" && echo "HOME=$HOME"`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "KEY=sk-") {
		t.Fatal("API key leaked into sandbox environment")
	}
	// HOME should be the sandbox workdir, not the user's home
	if !strings.Contains(res.Stdout, "rogue-sandbox") {
		t.Logf("HOME might not be sandbox workdir: %s", res.Stdout)
	}
}
