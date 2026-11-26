package arsenal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"rogue/internal/sandbox"
)

// CTFState holds global CTF challenge state for the current session.
type CTFState struct {
	mu         sync.Mutex
	challenges map[string]*ctfChallenge
	flags      map[string]string // challengeName -> captured flag
	docker     *sandbox.DockerRunner
}

type ctfChallenge struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	TargetURL   string `json:"target_url"`
	ContainerID string `json:"container_id,omitempty"`
	DockerImage string `json:"docker_image,omitempty"`
	Port        int    `json:"port,omitempty"`
	Hints       []string `json:"hints,omitempty"`
}

var globalCTF = &CTFState{
	challenges: make(map[string]*ctfChallenge),
	flags:      make(map[string]string),
	docker:     sandbox.DefaultDockerRunner(),
}

// RegisterCTFTools registers CTF-specific tools for challenge management,
// flag submission, and container orchestration.
func RegisterCTFTools(registry *Registry) {
	registry.Register(ctfSubmitFlagTool())
	registry.Register(ctfChallengeInfoTool())
	registry.Register(ctfStartContainerTool())
	registry.Register(ctfStopContainerTool())
	registry.Register(ctfListContainersTool())
}

// SetCTFChallenge sets the active CTF challenge context (called by benchmark runner).
func SetCTFChallenge(name, category, description, targetURL, dockerImage string, port int, hints []string) {
	globalCTF.mu.Lock()
	defer globalCTF.mu.Unlock()
	globalCTF.challenges[name] = &ctfChallenge{
		Name:        name,
		Category:    category,
		Description: description,
		TargetURL:   targetURL,
		DockerImage: dockerImage,
		Port:        port,
		Hints:       hints,
	}
}

// GetCapturedFlag returns the flag captured for a challenge, if any.
func GetCapturedFlag(name string) (string, bool) {
	globalCTF.mu.Lock()
	defer globalCTF.mu.Unlock()
	f, ok := globalCTF.flags[name]
	return f, ok
}

func ctfSubmitFlagTool() *Tool {
	return &Tool{
		Name:     "ctf_submit_flag",
		Category: "ctf",
		Internal: true,
		Description: "Submit a captured CTF flag for scoring. " +
			"The flag is recorded and can be verified against the expected answer.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"challenge": map[string]any{"type": "string", "description": "Name of the CTF challenge"},
			"flag":      map[string]any{"type": "string", "description": "The captured flag string"},
		}, "required": []string{"challenge", "flag"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Challenge string `json:"challenge"`
				Flag      string `json:"flag"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Challenge == "" || args.Flag == "" {
				return nil, errors.New("challenge name and flag are required")
			}

			globalCTF.mu.Lock()
			globalCTF.flags[args.Challenge] = args.Flag
			globalCTF.mu.Unlock()

			return &Result{
				Success: true,
				Data: map[string]any{
					"challenge":     args.Challenge,
					"flag_length":   len(args.Flag),
					"flag_recorded": true,
				},
				Summary: fmt.Sprintf("Flag submitted for challenge %q (%d chars)", args.Challenge, len(args.Flag)),
			}, nil
		},
	}
}

func ctfChallengeInfoTool() *Tool {
	return &Tool{
		Name:     "ctf_challenge_info",
		Category: "ctf",
		Internal: true,
		Description: "Get information about the current CTF challenge including " +
			"description, category, target URL, and available hints.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"challenge": map[string]any{"type": "string", "description": "Name of the CTF challenge (optional; returns all if empty)"},
		}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Challenge string `json:"challenge"`
			}
			_ = json.Unmarshal(raw, &args)

			globalCTF.mu.Lock()
			defer globalCTF.mu.Unlock()

			if args.Challenge != "" {
				ch, ok := globalCTF.challenges[args.Challenge]
				if !ok {
					return &Result{Success: false, Summary: fmt.Sprintf("Challenge %q not found", args.Challenge)}, nil
				}
				return &Result{
					Success: true,
					Data: map[string]any{
						"name":        ch.Name,
						"category":    ch.Category,
						"description": ch.Description,
						"target_url":  ch.TargetURL,
						"has_docker":  ch.DockerImage != "",
						"hints":       ch.Hints,
					},
					Summary: fmt.Sprintf("Challenge %q (%s)", ch.Name, ch.Category),
				}, nil
			}

			// Return all challenges
			var list []map[string]any
			for _, ch := range globalCTF.challenges {
				list = append(list, map[string]any{
					"name":     ch.Name,
					"category": ch.Category,
					"target":   ch.TargetURL,
				})
			}
			return &Result{
				Success: true,
				Data:    map[string]any{"challenges": list, "count": len(list)},
				Summary: fmt.Sprintf("%d active CTF challenges", len(list)),
			}, nil
		},
	}
}

func ctfStartContainerTool() *Tool {
	return &Tool{
		Name:     "ctf_start_container",
		Category: "ctf",
		LabOnly:  true,
		Description: "Start a Docker container for a CTF challenge. " +
			"Returns the mapped host port for accessing the challenge. " +
			"Requires Docker and ROGUE_LAB=true.",
		Available: func() error {
			return sandbox.DockerAvailable()
		},
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"image":    map[string]any{"type": "string", "description": "Docker image for the challenge"},
			"port":     map[string]any{"type": "integer", "description": "Container port to expose"},
			"challenge": map[string]any{"type": "string", "description": "Challenge name to associate with this container"},
		}, "required": []string{"image", "port"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Image     string `json:"image"`
				Port      int    `json:"port"`
				Challenge string `json:"challenge"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Image == "" || args.Port < 1 {
				return nil, errors.New("image and port are required")
			}

			container, err := globalCTF.docker.StartChallenge(ctx, args.Image, args.Port, 0)
			if err != nil {
				return nil, fmt.Errorf("failed to start challenge container: %w", err)
			}

			targetURL := fmt.Sprintf("http://127.0.0.1:%d", container.MappedPort)

			// Update challenge state if name provided
			if args.Challenge != "" {
				globalCTF.mu.Lock()
				if ch, ok := globalCTF.challenges[args.Challenge]; ok {
					ch.ContainerID = container.ID
					ch.TargetURL = targetURL
				} else {
					globalCTF.challenges[args.Challenge] = &ctfChallenge{
						Name:        args.Challenge,
						ContainerID: container.ID,
						DockerImage: args.Image,
						Port:        container.MappedPort,
						TargetURL:   targetURL,
					}
				}
				globalCTF.mu.Unlock()
			}

			return &Result{
				Success: true,
				Data: map[string]any{
					"container_id": container.ID,
					"image":        container.Image,
					"port":         container.Port,
					"mapped_port":  container.MappedPort,
					"target_url":   targetURL,
				},
				Summary: fmt.Sprintf("Challenge container started: %s → localhost:%d", args.Image, container.MappedPort),
			}, nil
		},
	}
}

func ctfStopContainerTool() *Tool {
	return &Tool{
		Name:     "ctf_stop_container",
		Category: "ctf",
		LabOnly:  true,
		Description: "Stop a running CTF challenge container.",
		Available: func() error {
			return sandbox.DockerAvailable()
		},
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"container_id": map[string]any{"type": "string", "description": "Container ID to stop"},
		}, "required": []string{"container_id"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				ContainerID string `json:"container_id"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.ContainerID == "" {
				return nil, errors.New("container_id is required")
			}

			if err := globalCTF.docker.StopChallenge(ctx, args.ContainerID); err != nil {
				return nil, fmt.Errorf("failed to stop container: %w", err)
			}

			return &Result{
				Success: true,
				Data:    map[string]any{"container_id": args.ContainerID, "stopped": true},
				Summary: fmt.Sprintf("Container %s stopped", args.ContainerID),
			}, nil
		},
	}
}

func ctfListContainersTool() *Tool {
	return &Tool{
		Name:     "ctf_list_containers",
		Category: "ctf",
		Internal: true,
		Description: "List all running ROGUE CTF challenge containers.",
		Available: func() error {
			return sandbox.DockerAvailable()
		},
		Parameters: map[string]any{"type": "object", "properties": map[string]any{}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			containers, err := globalCTF.docker.ListChallenges(ctx)
			if err != nil {
				return nil, err
			}

			var list []map[string]any
			for _, c := range containers {
				list = append(list, map[string]any{
					"id":    c.ID,
					"image": c.Image,
				})
			}

			return &Result{
				Success: true,
				Data:    map[string]any{"containers": list, "count": len(containers)},
				Summary: fmt.Sprintf("%d running CTF containers", len(containers)),
			}, nil
		},
	}
}

// sandboxEnabled is defined in sandbox_tools.go — this is intentionally not
// duplicated here; the functions share the same package.
