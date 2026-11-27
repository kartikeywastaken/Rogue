package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DockerRunner manages containerized CTF challenge environments.
type DockerRunner struct {
	// NetworkMode controls container networking. Default: "none" (isolated).
	NetworkMode string
	// MaxMemory caps container memory (e.g. "512m"). Default: "256m".
	MaxMemory string
	// CPUs limits CPU shares. Default: "1".
	CPUs string
}

// Container holds metadata about a running challenge container.
type Container struct {
	ID         string `json:"id"`
	Image      string `json:"image"`
	Port       int    `json:"port"`
	MappedPort int    `json:"mapped_port"`
	StartedAt  time.Time `json:"started_at"`
}

// DefaultDockerRunner returns a runner with safe defaults.
func DefaultDockerRunner() *DockerRunner {
	return &DockerRunner{
		NetworkMode: "bridge", // bridge for CTF challenges that need networking
		MaxMemory:   "256m",
		CPUs:        "1",
	}
}

// StartChallenge starts a Docker container for a CTF challenge.
// Returns the container info with the mapped host port.
func (d *DockerRunner) StartChallenge(ctx context.Context, image string, containerPort int, timeout time.Duration) (*Container, error) {
	if err := DockerAvailable(); err != nil {
		return nil, err
	}
	if image == "" {
		return nil, errors.New("container image is required")
	}
	if containerPort < 1 || containerPort > 65535 {
		return nil, errors.New("container port must be 1-65535")
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	mem := d.MaxMemory
	if mem == "" {
		mem = "256m"
	}
	cpus := d.CPUs
	if cpus == "" {
		cpus = "1"
	}
	net := d.NetworkMode
	if net == "" {
		net = "bridge"
	}

	args := []string{
		"run", "-d",
		"--rm",
		"--memory", mem,
		"--cpus", cpus,
		"--pids-limit", "256",
		"--security-opt", "no-new-privileges",
		"--network", net,
		"-p", fmt.Sprintf("127.0.0.1:0:%d", containerPort), // bind only on loopback
		"--label", "rogue.ctf=true",
		image,
	}

	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "docker", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker run failed: %w", err)
	}

	containerID := strings.TrimSpace(string(out))
	if len(containerID) < 12 {
		return nil, errors.New("docker did not return a valid container ID")
	}
	containerID = containerID[:12]

	// Get the mapped host port
	mappedPort, err := d.getMappedPort(ctx, containerID, containerPort)
	if err != nil {
		// Cleanup on failure
		_ = d.StopChallenge(ctx, containerID)
		return nil, err
	}

	c := &Container{
		ID:         containerID,
		Image:      image,
		Port:       containerPort,
		MappedPort: mappedPort,
		StartedAt:  time.Now(),
	}

	// Schedule auto-stop after timeout
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer stopCancel()
			_ = d.StopChallenge(stopCtx, containerID)
		case <-ctx.Done():
		}
	}()

	return c, nil
}

// StopChallenge stops and removes a container.
func (d *DockerRunner) StopChallenge(ctx context.Context, containerID string) error {
	if err := DockerAvailable(); err != nil {
		return err
	}
	if containerID == "" {
		return errors.New("container ID required")
	}

	execCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "docker", "stop", "-t", "5", containerID)
	return cmd.Run()
}

// getMappedPort inspects a container to find the host port mapping.
func (d *DockerRunner) getMappedPort(ctx context.Context, containerID string, containerPort int) (int, error) {
	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "docker", "inspect",
		"--format", fmt.Sprintf(`{{(index (index .NetworkSettings.Ports "%d/tcp") 0).HostPort}}`, containerPort),
		containerID)
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to inspect container port: %w", err)
	}

	portStr := strings.TrimSpace(string(out))
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port < 1 {
		return 0, fmt.Errorf("invalid mapped port: %s", portStr)
	}
	return port, nil
}

// ListChallenges lists running ROGUE CTF containers.
func (d *DockerRunner) ListChallenges(ctx context.Context) ([]Container, error) {
	if err := DockerAvailable(); err != nil {
		return nil, err
	}

	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "docker", "ps",
		"--filter", "label=rogue.ctf=true",
		"--format", `{"id":"{{.ID}}","image":"{{.Image}}","ports":"{{.Ports}}"}`)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	var containers []Container
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			ID    string `json:"id"`
			Image string `json:"image"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		containers = append(containers, Container{
			ID:    entry.ID,
			Image: entry.Image,
		})
	}
	return containers, nil
}
