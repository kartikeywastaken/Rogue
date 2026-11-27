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

type confinementConfig struct {
	WorkDir       string
	AllowNetwork  bool
	AllowLoopback bool
	LoopbackPort  int
}

// ConfinementAvailable reports whether OS-level filesystem and network
// confinement is supported and available on the current platform.
func ConfinementAvailable() error {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err != nil {
			return fmt.Errorf("macOS sandbox-exec not found in PATH: %w", err)
		}
		return nil
	case "linux":
		if _, err := exec.LookPath("bwrap"); err != nil {
			return fmt.Errorf("Linux bubblewrap (bwrap) not found in PATH: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("sandbox confinement not supported on %s", runtime.GOOS)
	}
}

// confinementAvailable preserves a boolean convenience helper for tests.
func confinementAvailable() bool {
	return ConfinementAvailable() == nil
}

// confineCommand wraps a command with OS-level filesystem and network
// confinement. On macOS it uses sandbox-exec with a Seatbelt profile;
// on Linux it uses bubblewrap (bwrap).
func confineCommand(ctx context.Context, cmd *exec.Cmd, cfg confinementConfig) (*exec.Cmd, func(), string, error) {
	switch runtime.GOOS {
	case "darwin":
		confined, cleanup, err := confineDarwin(ctx, cmd, cfg)
		return confined, cleanup, "seatbelt", err
	case "linux":
		confined, err := confineLinux(ctx, cmd, cfg)
		return confined, nil, "bwrap", err
	default:
		return nil, nil, "", fmt.Errorf("sandbox confinement not supported on %s", runtime.GOOS)
	}
}

// confineDarwin wraps the command using macOS sandbox-exec with a
// dynamically generated Seatbelt (.sb) profile placed outside workDir.
func confineDarwin(ctx context.Context, cmd *exec.Cmd, cfg confinementConfig) (*exec.Cmd, func(), error) {
	extraReadPaths := interpreterReadRoots(cmd.Path)
	profile := seatbeltProfile(cfg, extraReadPaths)

	pf, err := os.CreateTemp("", "rogue-sb-*.sb")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create seatbelt profile: %w", err)
	}
	profilePath := pf.Name()
	cleanup := func() { _ = os.Remove(profilePath) }

	if _, err := pf.WriteString(profile); err != nil {
		pf.Close()
		cleanup()
		return nil, nil, fmt.Errorf("failed to write seatbelt profile: %w", err)
	}
	if err := pf.Close(); err != nil {
		cleanup()
		return nil, nil, err
	}

	args := make([]string, 0, len(cmd.Args)+2)
	args = append(args, "-f", profilePath, cmd.Path)
	args = append(args, cmd.Args[1:]...)

	confined := exec.CommandContext(ctx, "sandbox-exec", args...)
	confined.Dir = cmd.Dir
	confined.Env = cmd.Env
	confined.Stdin = cmd.Stdin
	confined.Stdout = cmd.Stdout
	confined.Stderr = cmd.Stderr
	confined.WaitDelay = cmd.WaitDelay
	return confined, cleanup, nil
}

func interpreterReadRoots(binPath string) []string {
	if binPath == "" {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(binPath)
	if err != nil {
		resolved = binPath
	}
	// If the interpreter lives in a non-default toolchain root outside standard
	// system paths (and never broad roots or user homes), allow its prefix.
	dir := filepath.Dir(resolved)
	if filepath.Base(dir) == "bin" {
		dir = filepath.Dir(dir)
	}
	for _, unsafePrefix := range []string{"/Users", "/home", "/tmp", "/private/tmp", "/var", "/private/var"} {
		if dir == unsafePrefix || strings.HasPrefix(dir, unsafePrefix+"/") {
			return nil
		}
	}
	if dir == "/" {
		return nil
	}
	return []string{dir}
}

// seatbeltProfile generates a macOS Seatbelt profile that:
//   - Starts from bsd.sb (standard macOS dyld/runtime support without granting user or /tmp access)
//   - Allows read+write strictly within canonical cfg.WorkDir
//   - Allows read-only access to interpreter runtime directories
//   - Blocks all network when AllowNetwork == false && AllowLoopback == false,
//     permits only localhost[:port] when AllowLoopback == true,
//     or allows network when AllowNetwork == true.
func seatbeltProfile(cfg confinementConfig, extraReadPaths []string) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(import \"bsd.sb\")\n")
	sb.WriteString("(allow process-exec)\n")
	sb.WriteString("(allow process-fork)\n")

	// Runtime/interpreter read-only trees (never /Users, /tmp, or /private/var/folders).
	readOnlyPaths := []string{
		"/Library/Frameworks",
		"/Library/Developer/CommandLineTools",
		"/Applications/Xcode.app/Contents/Developer",
		"/opt/homebrew",
		"/usr/local",
		"/System/Cryptexes",
		"/System/Volumes/Preboot/Cryptexes",
	}
	readOnlyPaths = append(readOnlyPaths, extraReadPaths...)

	for _, p := range readOnlyPaths {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", p))
	}
	sb.WriteString("(allow file-map-executable)\n")

	// Read+write strictly within sandbox workDir.
	sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", cfg.WorkDir))
	sb.WriteString("(deny file-write*)\n")
	sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q) (literal \"/dev/null\") (literal \"/dev/zero\"))\n", cfg.WorkDir))
	sb.WriteString("(allow file-write-data (subpath \"/dev/fd\"))\n")

	// Network confinement.
	if cfg.AllowNetwork {
		sb.WriteString("(system-network)\n")
		sb.WriteString("(allow file-read* (literal \"/private/etc/hosts\") (literal \"/private/etc/resolv.conf\") (literal \"/private/var/run/resolv.conf\"))\n")
		sb.WriteString("(allow network*)\n")
	} else if cfg.AllowLoopback {
		sb.WriteString("(allow file-read* (literal \"/private/etc/hosts\"))\n")
		sb.WriteString("(deny network*)\n")
		remoteSpec := "localhost:*"
		if cfg.LoopbackPort > 0 {
			remoteSpec = fmt.Sprintf("localhost:%d", cfg.LoopbackPort)
		}
		sb.WriteString(fmt.Sprintf("(allow network-outbound (remote ip %q))\n", remoteSpec))
	} else {
		sb.WriteString("(deny network*)\n")
	}

	return sb.String()
}

// confineLinux wraps the command using bubblewrap (bwrap) for filesystem
// and network namespace isolation.
func confineLinux(ctx context.Context, cmd *exec.Cmd, cfg confinementConfig) (*exec.Cmd, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bubblewrap (bwrap) not found: %w", err)
	}

	args := []string{
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--bind", cfg.WorkDir, cfg.WorkDir,
		"--chdir", cfg.WorkDir,
		"--cap-drop", "ALL",
		"--new-session",
		"--die-with-parent",
	}

	// Bind existing system paths read-only, preserving symlinks on usr-merged systems.
	for _, p := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt"} {
		info, lerr := os.Lstat(p)
		if lerr != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if target, rerr := os.Readlink(p); rerr == nil {
				args = append(args, "--symlink", target, p)
				continue
			}
		}
		if info.IsDir() {
			args = append(args, "--ro-bind", p, p)
		}
	}

	if !cfg.AllowNetwork && !cfg.AllowLoopback {
		args = append(args, "--unshare-net")
	}

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
