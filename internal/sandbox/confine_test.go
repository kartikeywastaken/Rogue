package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestConfinementAvailable(t *testing.T) {
	available := confinementAvailable()
	t.Logf("confinement available on %s: %v", runtime.GOOS, available)
	if runtime.GOOS == "darwin" {
		if !available {
			t.Log("sandbox-exec not found — macOS confinement unavailable")
		}
	}
}

func TestConfinedExecBlocksFilesystemWrite(t *testing.T) {
	if !confinementAvailable() {
		t.Skip("OS-level confinement not available")
	}
	if err := Available("bash"); err != nil {
		t.Skip("bash not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	// Try to write outside the sandbox workdir — this should be blocked
	// by the seatbelt profile (macOS) or bwrap (Linux).
	targetFile := filepath.Join(os.TempDir(), "rogue-sandbox-escape-test.txt")
	defer os.Remove(targetFile) // cleanup in case confinement fails

	script := `echo "escaped" > ` + targetFile
	res, err := exec.ExecBash(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	// The script should either fail (non-zero exit) or the file should not exist
	if _, statErr := os.Stat(targetFile); statErr == nil {
		os.Remove(targetFile)
		t.Fatal("sandbox confinement FAILED: script wrote outside workdir")
	}
	t.Logf("filesystem confinement verified (exit=%d, stderr=%s)", res.ExitCode, strings.TrimSpace(res.Stderr))
}

func TestConfinedExecAllowsWorkdirWrite(t *testing.T) {
	if !confinementAvailable() {
		t.Skip("OS-level confinement not available")
	}
	if err := Available("bash"); err != nil {
		t.Skip("bash not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	// Writing inside the workdir should succeed
	res, err := exec.ExecBash(context.Background(), `echo "inside" > output.txt && cat output.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0 for workdir write, got %d: %s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "inside") {
		t.Fatalf("expected 'inside' in output, got %q", res.Stdout)
	}
}

func TestConfinedExecBlocksNetwork(t *testing.T) {
	if !confinementAvailable() {
		t.Skip("OS-level confinement not available")
	}
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	exec := DefaultExecutor()
	exec.AllowNetwork = false // explicitly deny network
	exec.Timeout = 10 * time.Second
	defer exec.Cleanup()

	// Try to make a network connection — should be blocked
	script := `
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("1.1.1.1", 80))
    print("CONNECTED")
    s.close()
    sys.exit(0)
except Exception as e:
    print(f"BLOCKED: {e}")
    sys.exit(1)
`
	res, err := exec.ExecPython(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "CONNECTED") {
		t.Fatal("sandbox confinement FAILED: network connection succeeded when AllowNetwork=false")
	}
	t.Logf("network confinement verified (exit=%d, stdout=%s)", res.ExitCode, strings.TrimSpace(res.Stdout))
}

func TestConfinedExecAllowsNetworkWhenEnabled(t *testing.T) {
	if !confinementAvailable() {
		t.Skip("OS-level confinement not available")
	}
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	exec := DefaultExecutor()
	exec.AllowNetwork = true
	exec.Timeout = 10 * time.Second
	defer exec.Cleanup()

	// A DNS lookup should work when network is allowed
	script := `
import socket
try:
    socket.getaddrinfo("localhost", 80)
    print("DNS_OK")
except Exception as e:
    print(f"FAIL: {e}")
`
	res, err := exec.ExecPython(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "DNS_OK") {
		t.Fatalf("expected DNS_OK when network allowed, got %q (stderr: %q)", res.Stdout, res.Stderr)
	}
}
