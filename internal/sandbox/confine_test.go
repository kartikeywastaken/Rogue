package sandbox

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestConfinementAvailable(t *testing.T) {
	err := ConfinementAvailable()
	t.Logf("confinement status on %s: err=%v", runtime.GOOS, err)
	if runtime.GOOS == "darwin" && err != nil {
		t.Fatalf("expected sandbox-exec confinement on darwin, got: %v", err)
	}
}

func TestConfinedExecBlocksFilesystemWriteAndSymlinkEscape(t *testing.T) {
	if err := ConfinementAvailable(); err != nil {
		t.Skip("OS-level confinement not available:", err)
	}
	if err := Available("bash"); err != nil {
		t.Skip("bash not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	outsideFile, err := os.CreateTemp("", "rogue-outside-write-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	outsidePath := outsideFile.Name()
	outsideFile.Close()
	os.Remove(outsidePath)
	defer os.Remove(outsidePath)

	// 1. Direct write outside workdir must fail.
	script := fmt.Sprintf(`echo "escaped" > %q`, outsidePath)
	res, err := exec.ExecBash(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Confined || res.Confinement == "" {
		t.Fatalf("expected confined execution metadata, got %+v", res)
	}
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit when writing outside workdir")
	}
	if _, statErr := os.Stat(outsidePath); statErr == nil {
		t.Fatal("sandbox confinement FAILED: script wrote directly outside workdir")
	}

	// 2. Symlink inside workdir pointing outside must also fail to write/read.
	symScript := fmt.Sprintf(`ln -s %q link_out && echo "via_symlink" > link_out`, outsidePath)
	res2, err := exec.ExecBash(context.Background(), symScript)
	if err != nil {
		t.Fatal(err)
	}
	if res2.ExitCode == 0 {
		t.Fatal("expected symlink escape write to fail")
	}
	if _, statErr := os.Stat(outsidePath); statErr == nil {
		t.Fatal("sandbox confinement FAILED: script wrote outside workdir via symlink")
	}

	// 3. Workdir WriteFile must refuse pre-existing symlinks on host side too.
	if _, err := exec.WriteFile("link_out", "host-side-overwrite"); err == nil {
		t.Fatal("expected Executor.WriteFile to reject existing symlink target")
	}
}

func TestConfinedExecBlocksHostSecretRead(t *testing.T) {
	if err := ConfinementAvailable(); err != nil {
		t.Skip("OS-level confinement not available:", err)
	}
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	secretFile, err := os.CreateTemp("", "rogue-host-secret-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	secretPath := secretFile.Name()
	_, _ = secretFile.WriteString("SUPER_SECRET_TOKEN_12345")
	secretFile.Close()
	defer os.Remove(secretPath)

	exec := DefaultExecutor()
	defer exec.Cleanup()

	script := fmt.Sprintf(`
import sys
try:
    with open(%q, "r") as f:
        print("LEAKED:", f.read())
    sys.exit(0)
except Exception as e:
    print("BLOCKED:", e)
    sys.exit(1)
`, secretPath)
	res, err := exec.ExecPython(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "SUPER_SECRET_TOKEN_12345") || res.ExitCode == 0 {
		t.Fatalf("sandbox confinement FAILED: host file read leaked (%+v)", res)
	}
}

func TestConfinedExecAllowsWorkdirWrite(t *testing.T) {
	if err := ConfinementAvailable(); err != nil {
		t.Skip("OS-level confinement not available:", err)
	}
	if err := Available("bash"); err != nil {
		t.Skip("bash not available:", err)
	}
	exec := DefaultExecutor()
	defer exec.Cleanup()

	res, err := exec.ExecBash(context.Background(), `echo "inside" > output.txt && cat output.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Confined {
		t.Fatalf("expected Confined=true, got %+v", res)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0 for workdir write, got %d: %s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "inside") {
		t.Fatalf("expected 'inside' in output, got %q", res.Stdout)
	}
}

func TestConfinedExecBlocksNetworkIncludingLoopback(t *testing.T) {
	if err := ConfinementAvailable(); err != nil {
		t.Skip("OS-level confinement not available:", err)
	}
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SHOULD_NOT_REACH"))
	}))
	defer srv.Close()

	exec := DefaultExecutor() // AllowNetwork=false, AllowLoopback=false
	exec.Timeout = 10 * time.Second
	defer exec.Cleanup()

	// Both local HTTP server AND external IP must be blocked.
	script := fmt.Sprintf(`
import socket, urllib.request, sys
try:
    r = urllib.request.urlopen(%q, timeout=2)
    print("LOCAL_LEAKED:", r.read().decode())
    sys.exit(0)
except Exception as e:
    print("LOCAL_BLOCKED:", e)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("1.1.1.1", 80))
    print("EXTERNAL_LEAKED")
    sys.exit(0)
except Exception as e:
    print("EXTERNAL_BLOCKED:", e)
    sys.exit(1)
`, srv.URL)

	res, err := exec.ExecPython(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "LEAKED") || res.ExitCode == 0 {
		t.Fatalf("network isolation FAILED when AllowNetwork=false: %+v", res)
	}
}

func TestConfinedExecAllowsScopedLoopbackOnly(t *testing.T) {
	if err := ConfinementAvailable(); err != nil {
		t.Skip("OS-level confinement not available:", err)
	}
	if runtime.GOOS != "darwin" {
		t.Skip("per-port loopback scoping verified via Seatbelt on darwin")
	}
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}

	allowedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SCOPED_TARGET_OK"))
	}))
	defer allowedSrv.Close()

	otherSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OTHER_PORT_LEAKED"))
	}))
	defer otherSrv.Close()

	var port int
	_, _ = fmt.Sscanf(strings.TrimPrefix(allowedSrv.URL, "http://127.0.0.1:"), "%d", &port)

	exec := DefaultExecutor()
	exec.AllowLoopback = true
	exec.LoopbackPort = port
	exec.Timeout = 10 * time.Second
	defer exec.Cleanup()

	script := fmt.Sprintf(`
import urllib.request, socket, sys
body = urllib.request.urlopen(%q, timeout=2).read().decode()
print("ALLOWED:", body)
try:
    urllib.request.urlopen(%q, timeout=2)
    print("OTHER_LEAKED")
    sys.exit(1)
except Exception as e:
    print("OTHER_BLOCKED:", e)
try:
    s = socket.socket()
    s.settimeout(2)
    s.connect(("1.1.1.1", 80))
    print("EXT_LEAKED")
    sys.exit(1)
except Exception as e:
    print("EXT_BLOCKED:", e)
`, allowedSrv.URL, otherSrv.URL)

	res, err := exec.ExecPython(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "ALLOWED: SCOPED_TARGET_OK") {
		t.Fatalf("scoped loopback verification failed: %+v", res)
	}
}

func TestConfinedExecAllowsNetworkWhenEnabled(t *testing.T) {
	if err := ConfinementAvailable(); err != nil {
		t.Skip("OS-level confinement not available:", err)
	}
	if err := Available("python3"); err != nil {
		t.Skip("python3 not available:", err)
	}
	exec := DefaultExecutor()
	exec.AllowNetwork = true
	exec.Timeout = 10 * time.Second
	defer exec.Cleanup()

	script := `
import socket
socket.getaddrinfo("localhost", 80)
print("DNS_OK")
`
	res, err := exec.ExecPython(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "DNS_OK") {
		t.Fatalf("expected DNS_OK when network allowed, got %+v", res)
	}
}

func TestExecutorRejectsBroadWorkDir(t *testing.T) {
	for _, bad := range []string{"/", filepath.Clean(os.TempDir())} {
		exec := DefaultExecutor()
		exec.WorkDir = bad
		if err := exec.ensureWorkDir(); err == nil {
			t.Fatalf("expected error for broad WorkDir %q", bad)
		}
	}
}
