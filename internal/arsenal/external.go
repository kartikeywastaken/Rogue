package arsenal

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"rogue/internal/target"
)

// Runner accepts an executable and separate arguments, never a shell command.
// Tests can replace the process boundary without adding a simulated UI backend.
type Runner interface {
	Run(context.Context, string, []string) ([]byte, error)
}

type ProcessRunner struct{}

type limitedBuffer struct {
	mu     sync.Mutex
	data   bytes.Buffer
	limit  int
	cancel context.CancelFunc
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if buffer.data.Len()+len(data) > buffer.limit {
		buffer.cancel()
		return 0, errors.New("tool output exceeded its capture limit")
	}
	return buffer.data.Write(data)
}

func (ProcessRunner) Run(parent context.Context, path string, arguments []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	output := &limitedBuffer{limit: 2 * 1024 * 1024, cancel: cancel}
	diagnostics := &limitedBuffer{limit: 16 * 1024, cancel: cancel}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Stdout = output
	command.Stderr = diagnostics
	// Discovery programs do not need access to the harness's API keys.
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C", "LC_ALL=C"}
	command.Stdin = strings.NewReader("")
	command.WaitDelay = time.Second
	err := command.Run()
	if err != nil && diagnostics.data.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(diagnostics.data.String()))
	}
	if ctx.Err() != nil {
		err = fmt.Errorf("external tool interrupted: %w", ctx.Err())
	}
	return slices.Clone(output.data.Bytes()), err
}

type ExternalOptions struct {
	Runner   Runner
	NmapPath string
	CurlPath string
	DigPath  string
}

func executable(name, configured string) (string, error) {
	if configured != "" {
		name = configured
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s is not installed or executable", name)
	}
	return path, nil
}

func RegisterExternalTools(registry *Registry, options ExternalOptions) {
	if options.Runner == nil {
		options.Runner = ProcessRunner{}
	}
	registry.Register(nmapTool(options))
	registry.Register(curlTool(options))
	registry.Register(digTool(options))
}

func selectedPorts(raw string) (string, error) {
	if raw == "" {
		return "22,80,443,8080,8443", nil
	}
	var ports []int
	for _, item := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("ports must be comma-separated numbers between 1 and 65535")
		}
		if !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
		if len(ports) > 256 {
			return "", errors.New("at most 256 ports are allowed in one external scan")
		}
	}
	slices.Sort(ports)
	values := make([]string, len(ports))
	for index, port := range ports {
		values[index] = strconv.Itoa(port)
	}
	return strings.Join(values, ","), nil
}

// An external scanner cannot use Go's guarded dialer. Pin it to one previously
// validated IP and disable its own DNS lookup, so it cannot resolve another peer.
func scopedAddress(ctx context.Context, host string) (string, error) {
	if err := checkHost(ctx, host); err != nil {
		return "", err
	}
	policy := ctx.Value(policyKey{}).(Policy)
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if policy.Rules.AllowsAddress(host, address.IP.String()) {
			return address.IP.String(), nil
		}
	}
	return "", errors.New("no resolved address is permitted by the mission rules")
}

func nmapTool(options ExternalOptions) *Tool {
	return &Tool{
		Name: "nmap_scan", Category: "recon",
		Description: "TCP connect and light service/version discovery using installed Nmap. Returns structured observed services; no scripts, exploit checks, or arbitrary flags.",
		Available:   func() error { _, err := executable("nmap", options.NmapPath); return err },
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"host":  map[string]any{"type": "string", "description": "One authorized hostname or IP"},
			"ports": map[string]any{"type": "string", "description": "Comma-separated numeric ports, at most 256; defaults to 22,80,443,8080,8443"},
		}, "required": []string{"host"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var arguments struct {
				Host  string `json:"host"`
				Ports string `json:"ports"`
			}
			if err := json.Unmarshal(raw, &arguments); err != nil {
				return nil, err
			}
			ports, err := selectedPorts(arguments.Ports)
			if err != nil {
				return nil, err
			}
			for _, port := range strings.Split(ports, ",") {
				if err := checkPort(ctx, port); err != nil {
					return nil, err
				}
			}
			address, err := scopedAddress(ctx, arguments.Host)
			if err != nil {
				return nil, err
			}
			path, err := executable("nmap", options.NmapPath)
			if err != nil {
				return nil, err
			}
			flags := []string{"-sT", "-Pn", "-n", "-sV", "--version-light", "--max-retries", "1", "--host-timeout", "45s", "-p", ports, "-oX", "-"}
			if strings.Contains(address, ":") {
				flags = append(flags, "-6")
			}
			flags = append(flags, address)
			output, err := options.Runner.Run(ctx, path, flags)
			if err != nil {
				return nil, fmt.Errorf("nmap failed: %w", err)
			}
			services, err := parseNmap(output, address)
			if err != nil {
				return nil, err
			}
			return &Result{Success: true, Data: map[string]any{"host": arguments.Host, "address": address, "services": services}, Summary: fmt.Sprintf("%s: %d observed open services", arguments.Host, len(services)), Artifact: output, ArtifactType: "application/xml"}, nil
		},
	}
}

func parseNmap(data []byte, address string) ([]target.Service, error) {
	var report struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Addresses []struct {
				Value string `xml:"addr,attr"`
			} `xml:"address"`
			Ports *struct {
				Values []struct {
					Number   int    `xml:"portid,attr"`
					Protocol string `xml:"protocol,attr"`
					State    struct {
						Value string `xml:"state,attr"`
					} `xml:"state"`
					Service struct {
						Name       string   `xml:"name,attr"`
						Product    string   `xml:"product,attr"`
						Version    string   `xml:"version,attr"`
						CPE        []string `xml:"cpe"`
						Method     string   `xml:"method,attr"`
						Confidence int      `xml:"conf,attr"`
					} `xml:"service"`
				} `xml:"port"`
			} `xml:"ports"`
		} `xml:"host"`
		Finished struct {
			Exit string `xml:"exit,attr"`
		} `xml:"runstats>finished"`
	}
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("invalid Nmap XML: %w", err)
	}
	if report.Finished.Exit != "success" {
		return nil, errors.New("Nmap did not report a completed scan")
	}
	if len(report.Hosts) == 0 {
		return nil, errors.New("Nmap returned no completed target record")
	}
	var services []target.Service
	for _, host := range report.Hosts {
		matched := false
		for _, peer := range host.Addresses {
			if net.ParseIP(peer.Value) != nil && net.ParseIP(peer.Value).Equal(net.ParseIP(address)) {
				matched = true
			}
		}
		if !matched {
			return nil, errors.New("Nmap output belongs to an unexpected target")
		}
		if host.Ports == nil {
			return nil, errors.New("Nmap target has no completed port results; it may have timed out")
		}
		for _, port := range host.Ports.Values {
			if port.State.Value != "open" {
				continue
			}
			if port.Number < 1 || port.Number > 65535 || port.Protocol != "tcp" {
				return nil, errors.New("invalid service in Nmap output")
			}
			services = append(services, target.Service{Port: port.Number, Protocol: port.Protocol, Name: port.Service.Name, Product: port.Service.Product, Version: port.Service.Version, CPE: port.Service.CPE, Method: port.Service.Method, Confidence: port.Service.Confidence})
		}
	}
	return services, nil
}

func curlTool(options ExternalOptions) *Tool {
	return &Tool{
		Name: "curl_request", Category: "recon",
		Description: "Fetch response headers with installed curl. Uses one scoped, pinned peer and does not follow redirects or load curl configuration files.",
		Available:   func() error { _, err := executable("curl", options.CurlPath); return err },
		Parameters:  map[string]any{"type": "object", "properties": map[string]any{"url": map[string]any{"type": "string", "description": "Authorized HTTP(S) URL"}}, "required": []string{"url"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var arguments struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(raw, &arguments); err != nil {
				return nil, err
			}
			parsed, err := checkURL(ctx, arguments.URL)
			if err != nil {
				return nil, err
			}
			address, err := scopedAddress(ctx, parsed.Hostname())
			if err != nil {
				return nil, err
			}
			path, err := executable("curl", options.CurlPath)
			if err != nil {
				return nil, err
			}
			port := parsed.Port()
			if port == "" {
				port = "80"
				if parsed.Scheme == "https" {
					port = "443"
				}
			}
			if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
				return nil, errors.New("invalid URL port")
			}
			if strings.Contains(address, ":") {
				address = "[" + address + "]"
			}
			flags := []string{"-q", "--head", "--silent", "--show-error", "--max-time", "20", "--max-redirs", "0", "--proto", "=http,https", "--noproxy", "*", "--resolve", parsed.Hostname() + ":" + port + ":" + address, "--url", parsed.String()}
			output, err := options.Runner.Run(ctx, path, flags)
			if err != nil {
				return nil, fmt.Errorf("curl failed: %w", err)
			}
			// The command returns headers only, with a hard capture limit in Runner.
			headers := make(map[string]string)
			for _, line := range strings.Split(string(output), "\n") {
				if name, value, found := strings.Cut(line, ":"); found && !strings.HasPrefix(line, "HTTP/") {
					headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
				}
			}
			return &Result{Success: true, Data: map[string]any{"url": parsed.String(), "headers": headers, "raw_headers": string(output)}, Summary: "response headers retrieved with curl"}, nil
		},
	}
}

// Keep imports local to this implementation rather than exposing command strings
// or output streams as capabilities available to the model.
var _ io.Writer = (*limitedBuffer)(nil)
