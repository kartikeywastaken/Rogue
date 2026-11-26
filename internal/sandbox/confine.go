package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// confinementAvailable reports whether OS-level process confinement is
// supported on the current platform.
func confinementAvailable() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := exec.LookPath("sandbox-exec")
		return err == nil
	case "linux":
		_, err := exec.LookPath("bwrap")
		return err == nil
	default:
		return false
	}
}

// confineCommand wraps a command with OS-level filesystem and network
// confinement. On macOS it uses sandbox-exec with a Seatbelt profile;
// on Linux it uses bubblewrap (bwrap). The returned command replaces
// the original and enforces:
//   - Filesystem writes confined to workDir
//   - Network access blocked when allowNetwork is false
//   - Read-only access to system paths (/usr, /System, interpreters, etc.)
//
// If confinement is unavailable, it returns an error rather than silently
// running unconfined.
func confineCommand(ctx context.Context, cmd *exec.Cmd, workDir string, allowNetwork bool) (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "darwin":
		return confineDarwin(ctx, cmd, workDir, allowNetwork)
	case "linux":
		return confineLinux(ctx, cmd, workDir, allowNetwork)
	default:
		return nil, fmt.Errorf("sandbox confinement not supported on %s", runtime.GOOS)
	}
}

// confineDarwin wraps the command using macOS sandbox-exec with a
// dynamically generated Seatbelt (.sb) profile.
func confineDarwin(ctx context.Context, cmd *exec.Cmd, workDir string, allowNetwork bool) (*exec.Cmd, error) {
	profile := seatbeltProfile(workDir, allowNetwork)

	// Write the profile to a temp file in workDir so it's accessible
	profilePath := filepath.Join(workDir, ".sandbox-profile.sb")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write seatbelt profile: %w", err)
	}

	// Build the sandbox-exec command wrapping the original
	args := []string{"-f", profilePath}
	args = append(args, cmd.Path)
	args = append(args, cmd.Args[1:]...) // cmd.Args[0] is the program name

	confined := exec.CommandContext(ctx, "sandbox-exec", args...)
	confined.Dir = cmd.Dir
	confined.Env = cmd.Env
	confined.Stdin = cmd.Stdin
	confined.Stdout = cmd.Stdout
	confined.Stderr = cmd.Stderr
	confined.WaitDelay = cmd.WaitDelay
	return confined, nil
}

// seatbeltProfile generates a macOS Seatbelt profile that:
//   - Denies all by default
//   - Allows read+write in workDir
//   - Allows read-only access to system paths needed for interpreters
//   - Blocks or allows network based on allowNetwork
func seatbeltProfile(workDir string, allowNetwork bool) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")

	// Allow basic process operations
	sb.WriteString("(allow process-exec)\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow signal (target self))\n")
	sb.WriteString("(allow sysctl-read)\n")
	sb.WriteString("(allow mach-lookup)\n")
	sb.WriteString("(allow ipc-posix-shm-read-data)\n")
	sb.WriteString("(allow ipc-posix-shm-write-data)\n")
	sb.WriteString("(allow ipc-posix-shm-write-create)\n")

	// Read-only access to system paths needed by interpreters
	readOnlyPaths := []string{
		"/usr/lib",
		"/usr/bin",
		"/usr/local",
		"/bin",
		"/sbin",
		"/System",
		"/Library/Frameworks",
		"/dev/null",
		"/dev/urandom",
		"/dev/random",
		"/dev/zero",
		"/dev/fd",
		"/dev/tty",
		"/dev/stdin",
		"/dev/stdout",
		"/dev/stderr",
		"/private/var/db",
		"/private/etc",
		"/etc",
		"/var",
	}

	// Homebrew paths (common interpreter locations)
	homebrewPaths := []string{
		"/opt/homebrew",
		"/usr/local/Cellar",
		"/usr/local/opt",
		"/usr/local/lib",
		"/usr/local/bin",
		"/usr/local/Frameworks",
	}
	readOnlyPaths = append(readOnlyPaths, homebrewPaths...)

	// Python framework paths
	pythonPaths := []string{
		"/Library/Frameworks/Python.framework",
		"/Applications/Xcode.app/Contents/Developer",
	}
	readOnlyPaths = append(readOnlyPaths, pythonPaths...)

	for _, p := range readOnlyPaths {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", p))
	}

	// Allow read+write to the sandbox workdir
	sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", workDir))
	sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", workDir))

	// Allow writing to /dev/null (some scripts redirect there)
	sb.WriteString("(allow file-write* (literal \"/dev/null\"))\n")

	// Allow temp writes for Python bytecache etc. inside the workdir
	// (HOME and TMPDIR are set to workDir in the executor)

	// Network policy
	if allowNetwork {
		sb.WriteString("(allow network*)\n")
	} else {
		sb.WriteString("; network access denied\n")
	}

	return sb.String()
}

// confineLinux wraps the command using bubblewrap (bwrap) for filesystem
// and network namespace isolation.
func confineLinux(ctx context.Context, cmd *exec.Cmd, workDir string, allowNetwork bool) (*exec.Cmd, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bubblewrap (bwrap) not found: %w", err)
	}

	args := []string{
		// Read-only bind mounts for system paths
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
		"--ro-bind", "/etc", "/etc",
		"--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc",
		"--dev", "/dev",
		// Writable bind mount for the sandbox workdir
		"--bind", workDir, workDir,
		// Private tmpdir
		"--tmpfs", "/tmp",
		// Chdir into workdir
		"--chdir", workDir,
		// Drop all caps
		"--cap-drop", "ALL",
		// New PID namespace
		"--new-session",
		"--die-with-parent",
	}

	// Network isolation
	if !allowNetwork {
		args = append(args, "--unshare-net")
	}

	// Homebrew / optional paths
	for _, p := range []string{"/opt", "/usr/local"} {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			args = append(args, "--ro-bind", p, p)
		}
	}

	// Add the actual command
	args = append(args, cmd.Path)
	args = append(args, cmd.Args[1:]...)

	confined := exec.CommandContext(ctx, bwrap, args...)
	confined.Dir = cmd.Dir
	confined.Env = cmd.Env
	confined.Stdin = cmd.Stdin
	confined.Stdout = cmd.Stdout
	confined.Stderr = cmd.Stderr
	confined.WaitDelay = cmd.WaitDelay
	return confined, nil
}
