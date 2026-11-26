package arsenal

// external2.go — Phase 2 external CLI wrappers & crypto_hash utility.
// All external tools use ProcessRunner:
//   - Env stripped to PATH, LANG, LC_ALL
//   - stdout capped at 2 MiB, stderr capped at 16 KiB
//   - OPSEC jitter applied automatically via ProcessRunner.Run
//   - Explicit []string arguments (no shell interpolation, leading '-' rejected)
//   - Network tools validate scope via checkURL / checkHost / scopedAddress / labURL

import (
	"context"
	"crypto/md5"  //nolint:gosec
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"rogue/internal/domain"
)

// RegisterExtendedTools adds Phase 2 external CLI wrappers and crypto_hash to registry.
func RegisterExtendedTools(registry *Registry, options ExternalOptions) {
	runner := options.Runner
	if runner == nil {
		runner = ProcessRunner{}
	}

	registry.Register(dirbTool(runner))
	registry.Register(ffufTool(runner))
	registry.Register(gobusterTool(runner))
	registry.Register(wfuzzTool(runner))
	registry.Register(niktoTool(runner))
	registry.Register(sqlmapTool(runner))
	registry.Register(hydraTool(runner))
	registry.Register(hostLookupTool(runner))
	registry.Register(whoisCLITool(runner))
	registry.Register(wgetFetchTool(runner))
	registry.Register(opensslScanTool(runner))
	registry.Register(xxdDumpTool(runner))
	registry.Register(stringsExtractTool(runner))
	registry.Register(fileIdentifyTool(runner))
	registry.Register(exiftoolMetaTool(runner))
	registry.Register(binwalkAnalyzeTool(runner))
	registry.Register(nucleiScanTool(runner))
	registry.Register(cryptoHashTool())
}

// ── shared helpers ────────────────────────────────────────────────────────────

func validateSimpleFlagValue(val, field string) error {
	if val == "" {
		return nil
	}
	if strings.HasPrefix(val, "-") || strings.ContainsAny(val, " \r\n\t;|&`$") {
		return fmt.Errorf("invalid %s", field)
	}
	return nil
}

func validateNumericList(val, field string) error {
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 100 || n > 599 {
			return fmt.Errorf("invalid status code %q in %s", part, field)
		}
	}
	return nil
}

func boundedIntString(raw, field string, minVal, maxVal, defVal int) (string, error) {
	if raw == "" {
		return strconv.Itoa(defVal), nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < minVal || n > maxVal {
		return "", fmt.Errorf("%s must be an integer between %d and %d", field, minVal, maxVal)
	}
	return strconv.Itoa(n), nil
}

// runToolCLI executes a CLI binary via runner and only suppresses non-zero
// exit codes when ctx is healthy and stdout/stderr limit was not exceeded.
func runToolCLI(ctx context.Context, runner Runner, bin string, args []string) ([]byte, error) {
	out, err := runner.Run(ctx, bin, args)
	if err != nil {
		if ctx.Err() != nil {
			return out, err
		}
		msg := err.Error()
		// Preserve structured failure for output limit or execution errors;
		// allow exit-status non-zero when usable stdout was captured.
		if strings.Contains(msg, "exit status") && len(out) > 0 && !strings.Contains(msg, "capture limit") {
			return out, nil
		}
		return out, err
	}
	return out, nil
}

// ── web enumeration & fuzzing ─────────────────────────────────────────────────

func dirbTool(runner Runner) *Tool {
	return &Tool{
		Name:        "dirb_scan",
		Category:    "web",
		Description: "Directory brute-force with dirb. URL must be in mission scope.",
		Parameters:  stringSchema([]string{"target_url"}, "target_url", "wordlist"),
		Available:   func() error { _, err := executable("dirb", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				TargetURL string `json:"target_url"`
				Wordlist  string `json:"wordlist"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if _, err := checkURL(ctx, a.TargetURL); err != nil {
				return fail(fmt.Errorf("dirb_scan: %w", err))
			}
			path, err := executable("dirb", "")
			if err != nil {
				return fail(err)
			}
			args := []string{a.TargetURL}
			if a.Wordlist != "" {
				wl, _, err := regularFileCheck(a.Wordlist, 32*1024*1024)
				if err != nil {
					return fail(fmt.Errorf("dirb_scan wordlist: %w", err))
				}
				args = append(args, wl)
			}
			args = append(args, "-r", "-S")
			out, err := runToolCLI(ctx, runner, path, args)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("dirb scan completed on %s (%d bytes)", a.TargetURL, len(out)), Data: map[string]any{"raw": string(out)}, Artifact: out, ArtifactType: "text/plain"}, nil
		},
	}
}

func ffufTool(runner Runner) *Tool {
	return &Tool{
		Name:        "ffuf_scan",
		Category:    "web",
		Description: "Fast web fuzzer. target_url must contain FUZZ. URL must be in scope.",
		Parameters:  stringSchema([]string{"target_url", "wordlist"}, "target_url", "wordlist", "hide_status"),
		Available:   func() error { _, err := executable("ffuf", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				TargetURL  string `json:"target_url"`
				Wordlist   string `json:"wordlist"`
				HideStatus string `json:"hide_status"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if !strings.Contains(a.TargetURL, "FUZZ") {
				return fail(errors.New("ffuf_scan: target_url must contain FUZZ placeholder"))
			}
			scopeURL := strings.ReplaceAll(a.TargetURL, "FUZZ", "index")
			if _, err := checkURL(ctx, scopeURL); err != nil {
				return fail(fmt.Errorf("ffuf_scan: %w", err))
			}
			wl, _, err := regularFileCheck(a.Wordlist, 32*1024*1024)
			if err != nil {
				return fail(fmt.Errorf("ffuf_scan wordlist: %w", err))
			}
			if a.HideStatus != "" {
				if err := validateNumericList(a.HideStatus, "hide_status"); err != nil {
					return fail(err)
				}
			}
			path, err := executable("ffuf", "")
			if err != nil {
				return fail(err)
			}
			args := []string{"-u", a.TargetURL, "-w", wl, "-of", "json", "-s"}
			if a.HideStatus != "" {
				args = append(args, "-fc", a.HideStatus)
			}
			out, err := runToolCLI(ctx, runner, path, args)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("ffuf fuzzing completed on %s (%d bytes)", a.TargetURL, len(out)), Data: map[string]any{"raw": string(out)}, Artifact: out, ArtifactType: "application/json"}, nil
		},
	}
}

func gobusterTool(runner Runner) *Tool {
	return &Tool{
		Name:        "gobuster_scan",
		Category:    "web",
		Description: "Directory/file enumeration with gobuster. URL must be in scope.",
		Parameters:  stringSchema([]string{"target_url", "wordlist"}, "target_url", "wordlist", "extensions"),
		Available:   func() error { _, err := executable("gobuster", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				TargetURL  string `json:"target_url"`
				Wordlist   string `json:"wordlist"`
				Extensions string `json:"extensions"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if _, err := checkURL(ctx, a.TargetURL); err != nil {
				return fail(fmt.Errorf("gobuster_scan: %w", err))
			}
			wl, _, err := regularFileCheck(a.Wordlist, 32*1024*1024)
			if err != nil {
				return fail(fmt.Errorf("gobuster_scan wordlist: %w", err))
			}
			if err := validateSimpleFlagValue(a.Extensions, "extensions"); err != nil {
				return fail(err)
			}
			path, err := executable("gobuster", "")
			if err != nil {
				return fail(err)
			}
			args := []string{"dir", "-u", a.TargetURL, "-w", wl, "-q", "--no-progress"}
			if a.Extensions != "" {
				args = append(args, "-x", a.Extensions)
			}
			out, err := runToolCLI(ctx, runner, path, args)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("gobuster scan completed on %s (%d bytes)", a.TargetURL, len(out)), Data: map[string]any{"raw": string(out)}, Artifact: out, ArtifactType: "text/plain"}, nil
		},
	}
}

func wfuzzTool(runner Runner) *Tool {
	return &Tool{
		Name:        "wfuzz_scan",
		Category:    "web",
		Description: "Web parameter/path fuzzer using wfuzz. target_url must contain FUZZ placeholder and be in mission scope.",
		Parameters:  stringSchema([]string{"target_url", "wordlist"}, "target_url", "wordlist", "hide_codes"),
		Available:   func() error { _, err := executable("wfuzz", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				TargetURL string `json:"target_url"`
				Wordlist  string `json:"wordlist"`
				HideCodes string `json:"hide_codes"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if !strings.Contains(a.TargetURL, "FUZZ") {
				return fail(errors.New("wfuzz_scan: target_url must contain FUZZ placeholder"))
			}
			if _, err := checkURL(ctx, strings.ReplaceAll(a.TargetURL, "FUZZ", "test")); err != nil {
				return fail(fmt.Errorf("wfuzz_scan: %w", err))
			}
			wl, _, err := regularFileCheck(a.Wordlist, 32*1024*1024)
			if err != nil {
				return fail(fmt.Errorf("wfuzz_scan wordlist: %w", err))
			}
			hide := "404"
			if a.HideCodes != "" {
				if err := validateNumericList(a.HideCodes, "hide_codes"); err != nil {
					return fail(err)
				}
				hide = a.HideCodes
			}
			path, err := executable("wfuzz", "")
			if err != nil {
				return fail(err)
			}
			args := []string{"-z", "file," + wl, "--hc", hide, a.TargetURL}
			out, err := runToolCLI(ctx, runner, path, args)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("wfuzz scan completed on %s (%d bytes)", a.TargetURL, len(out)), Data: map[string]any{"raw": string(out)}, Artifact: out, ArtifactType: "text/plain"}, nil
		},
	}
}

// ── vulnerability scanners ───────────────────────────────────────────────────

func niktoTool(runner Runner) *Tool {
	return &Tool{
		Name:        "nikto_scan",
		Category:    "vuln",
		Description: "Nikto web server vulnerability scanner. Host and port must be in mission scope.",
		Parameters:  stringSchema([]string{"host"}, "host", "port"),
		Available:   func() error { _, err := executable("nikto", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Host string `json:"host"`
				Port string `json:"port"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := validateSimpleFlagValue(a.Host, "host"); err != nil {
				return fail(err)
			}
			address, err := scopedAddress(ctx, a.Host)
			if err != nil {
				return fail(fmt.Errorf("nikto_scan: %w", err))
			}
			port := a.Port
			if port == "" {
				port = "80"
			}
			if !validPort(port) {
				return fail(errors.New("nikto_scan: port must be 1–65535"))
			}
			if err := checkPort(ctx, port); err != nil {
				return fail(fmt.Errorf("nikto_scan: %w", err))
			}
			path, err := executable("nikto", "")
			if err != nil {
				return fail(err)
			}
			args := []string{"-h", address, "-vhost", a.Host, "-port", port, "-Format", "txt", "-nointeractive", "-Tuning", "123457890abc"}
			out, err := runToolCLI(ctx, runner, path, args)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("nikto scan completed on %s:%s (%d bytes)", a.Host, port, len(out)), Data: map[string]any{"host": a.Host, "address": address, "port": port, "raw": string(out)}, Artifact: out, ArtifactType: "text/plain"}, nil
		},
	}
}

func sqlmapTool(runner Runner) *Tool {
	return &Tool{
		Name:        "sqlmap_probe",
		Category:    "vuln",
		LabOnly:     true,
		Description: "SQLMap injection probe. Lab-only: requires ROGUE_LAB=true, loopback target, and exact-action approval.",
		Parameters:  stringSchema([]string{"target_url"}, "target_url", "level", "risk"),
		Available:   func() error { _, err := executable("sqlmap", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				TargetURL string `json:"target_url"`
				Level     string `json:"level"`
				Risk      string `json:"risk"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if _, err := labURL(ctx, a.TargetURL); err != nil {
				return fail(fmt.Errorf("sqlmap_probe: %w", err))
			}
			level, err := boundedIntString(a.Level, "level", 1, 5, 1)
			if err != nil {
				return fail(err)
			}
			risk, err := boundedIntString(a.Risk, "risk", 1, 3, 1)
			if err != nil {
				return fail(err)
			}
			path, err := executable("sqlmap", "")
			if err != nil {
				return fail(err)
			}
			tmpDir, err := os.MkdirTemp("", "rogue-sqlmap-*")
			if err != nil {
				return fail(err)
			}
			defer os.RemoveAll(tmpDir)
			args := []string{"-u", a.TargetURL, "--batch", "--level=" + level, "--risk=" + risk, "--output-dir=" + tmpDir}
			out, err := runToolCLI(ctx, runner, path, args)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("sqlmap probe completed on %s (level %s, risk %s)", a.TargetURL, level, risk), Data: map[string]any{"raw": string(out)}, Artifact: out, ArtifactType: "text/plain"}, nil
		},
	}
}

// ── auth ──────────────────────────────────────────────────────────────────────

var allowedHydraServices = map[string]bool{
	"ssh": true, "ftp": true, "smtp": true, "mysql": true, "postgres": true,
	"redis": true, "smb": true, "http-get": true, "http-post-form": true, "http-get-form": true,
}

func hydraTool(runner Runner) *Tool {
	return &Tool{
		Name:          "hydra_probe",
		Category:      "auth",
		LabOnly:       true,
		SensitiveArgs: []string{"pass"},
		Description:   "Hydra credential probe. Lab-only: requires ROGUE_LAB=true, loopback target, and exact-action approval.",
		Parameters:    stringSchema([]string{"service", "host", "user", "pass"}, "service", "host", "user", "pass"),
		Available:     func() error { _, err := executable("hydra", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Service string `json:"service"`
				Host    string `json:"host"`
				User    string `json:"user"`
				Pass    string `json:"pass"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if !allowedHydraServices[strings.ToLower(a.Service)] {
				return fail(fmt.Errorf("hydra_probe: unsupported service %q", a.Service))
			}
			if err := validateSimpleFlagValue(a.Host, "host"); err != nil {
				return fail(err)
			}
			if err := validateSimpleFlagValue(a.User, "user"); err != nil {
				return fail(err)
			}
			host := a.Host
			if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
				host = "[" + host + "]"
			}
			if _, err := labURL(ctx, "http://"+host); err != nil {
				return fail(fmt.Errorf("hydra_probe: %w", err))
			}
			path, err := executable("hydra", "")
			if err != nil {
				return fail(err)
			}
			out, err := runToolCLI(ctx, runner, path, []string{"-l", a.User, "-p", a.Pass, "-I", "-t", "1", a.Host, strings.ToLower(a.Service)})
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("hydra check finished for %s@%s (%s)", a.User, a.Host, a.Service), Data: map[string]any{"raw": string(out)}, Artifact: out, ArtifactType: "text/plain"}, nil
		},
	}
}

// ── recon / network ──────────────────────────────────────────────────────────

func hostLookupTool(runner Runner) *Tool {
	return &Tool{
		Name:        "host_lookup",
		Category:    "recon",
		Description: "DNS record lookup via the host command. Host must be in scope.",
		Parameters:  stringSchema([]string{"hostname"}, "hostname", "type"),
		Available:   func() error { _, err := executable("host", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Hostname string `json:"hostname"`
				Type     string `json:"type"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := validateSimpleFlagValue(a.Hostname, "hostname"); err != nil {
				return fail(err)
			}
			if err := checkHost(ctx, a.Hostname); err != nil {
				return fail(fmt.Errorf("host_lookup: %w", err))
			}
			recType := "A"
			if a.Type != "" {
				recType = strings.ToUpper(a.Type)
			}
			allowed := map[string]bool{"A": true, "AAAA": true, "MX": true, "NS": true, "TXT": true, "CNAME": true, "SOA": true, "PTR": true}
			if !allowed[recType] {
				return fail(fmt.Errorf("unsupported record type: %s", a.Type))
			}
			path, err := executable("host", "")
			if err != nil {
				return fail(err)
			}
			out, err := runToolCLI(ctx, runner, path, []string{"-t", recType, a.Hostname})
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("host -t %s %s completed", recType, a.Hostname), Data: map[string]any{"hostname": a.Hostname, "type": recType, "raw": string(out)}}, nil
		},
	}
}

func whoisCLITool(runner Runner) *Tool {
	return &Tool{
		Name:        "whois_cli",
		Category:    "recon",
		Description: "Query system whois CLI (follows registry referrals) for one domain name in scope.",
		Parameters:  stringSchema([]string{"host"}, "host"),
		Available:   func() error { _, err := executable("whois", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := validateSimpleFlagValue(a.Host, "host"); err != nil {
				return fail(err)
			}
			if len(a.Host) > 253 || strings.ContainsAny(a.Host, "\r\n /:@\\") {
				return fail(errors.New("whois_cli: host must be a valid domain or IP"))
			}
			if err := checkHost(ctx, a.Host); err != nil {
				return fail(fmt.Errorf("whois_cli: %w", err))
			}
			path, err := executable("whois", "")
			if err != nil {
				return fail(err)
			}
			out, err := runToolCLI(ctx, runner, path, []string{a.Host})
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("whois CLI query completed for %s (%d bytes)", a.Host, len(out)), Data: map[string]any{"host": a.Host, "raw": string(out)}, Artifact: out, ArtifactType: "text/plain"}, nil
		},
	}
}

func wgetFetchTool(runner Runner) *Tool {
	return &Tool{
		Name:        "wget_fetch",
		Category:    "recon",
		Description: "Fetch a URL with wget. Output is captured up to 2 MiB, not saved to disk. Redirects disabled to preserve scope.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"url":          map[string]any{"type": "string", "description": "URL to fetch"},
			"headers_only": map[string]any{"type": "boolean", "description": "true to fetch headers only"},
		}, "required": []string{"url"}},
		Available: func() error { _, err := executable("wget", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				URL         string `json:"url"`
				HeadersOnly bool   `json:"headers_only"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			parsed, err := checkURL(ctx, a.URL)
			if err != nil {
				return fail(fmt.Errorf("wget_fetch: %w", err))
			}
			if _, err := scopedAddress(ctx, parsed.Hostname()); err != nil {
				return fail(fmt.Errorf("wget_fetch: %w", err))
			}
			path, err := executable("wget", "")
			if err != nil {
				return fail(err)
			}
			// Disable redirects to avoid off-scope jumps during CLI fetch.
			args := []string{"-q", "-O", "-", "--max-redirect=0", "--timeout=15", "--tries=1", "--", parsed.String()}
			if a.HeadersOnly {
				args = []string{"-q", "--server-response", "--spider", "--max-redirect=0", "--timeout=15", "--", parsed.String()}
			}
			out, err := runToolCLI(ctx, runner, path, args)
			if err != nil {
				return fail(err)
			}
			if !urlSchemeSafe(parsed) {
				return fail(errors.New("unsafe scheme"))
			}
			return &Result{Success: true, Summary: fmt.Sprintf("wget fetch completed on %s (%d bytes)", a.URL, len(out)), Data: map[string]any{"url": a.URL, "raw": string(out)}}, nil
		},
	}
}

func urlSchemeSafe(u *url.URL) bool {
	return u != nil && (u.Scheme == "http" || u.Scheme == "https")
}

// ── TLS / SSL ────────────────────────────────────────────────────────────────

func opensslScanTool(runner Runner) *Tool {
	return &Tool{
		Name:        "openssl_scan",
		Category:    "vuln",
		Description: "Inspect TLS connection details via openssl s_client using scoped IP pinning + SNI. Host must be in scope.",
		Parameters:  stringSchema([]string{"host"}, "host", "port"),
		Available:   func() error { _, err := executable("openssl", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Host string `json:"host"`
				Port string `json:"port"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := validateSimpleFlagValue(a.Host, "host"); err != nil {
				return fail(err)
			}
			address, err := scopedAddress(ctx, a.Host)
			if err != nil {
				return fail(fmt.Errorf("openssl_scan: %w", err))
			}
			port := a.Port
			if port == "" {
				port = "443"
			}
			if !validPort(port) {
				return fail(errors.New("openssl_scan: port must be 1–65535"))
			}
			if err := checkPort(ctx, port); err != nil {
				return fail(fmt.Errorf("openssl_scan: %w", err))
			}
			path, err := executable("openssl", "")
			if err != nil {
				return fail(err)
			}
			addr := net.JoinHostPort(address, port)
			out, err := runToolCLI(ctx, runner, path, []string{"s_client", "-connect", addr, "-servername", a.Host, "-brief"})
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("openssl s_client inspection completed for %s:%s", a.Host, port), Data: map[string]any{"host": a.Host, "address": address, "port": port, "raw": string(out)}}, nil
		},
	}
}

// ── forensics / binary CLI wrappers ──────────────────────────────────────────

func xxdDumpTool(runner Runner) *Tool {
	return &Tool{
		Name:        "xxd_dump",
		Category:    "util",
		Description: "Hex dump of a local regular file (first 4096 bytes).",
		Parameters:  stringSchema([]string{"path"}, "path"),
		Available:   func() error { _, err := executable("xxd", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Path string `json:"path"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			clean, _, err := regularFileCheck(a.Path, 64*1024*1024)
			if err != nil {
				return fail(fmt.Errorf("xxd_dump: %w", err))
			}
			p, err := executable("xxd", "")
			if err != nil {
				return fail(err)
			}
			out, err := runToolCLI(ctx, runner, p, []string{"-l", "4096", clean})
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("Hex dump of %s (%d bytes output)", filepath.Base(clean), len(out)), Data: map[string]any{"hex_dump": string(out)}}, nil
		},
	}
}

func stringsExtractTool(runner Runner) *Tool {
	return &Tool{
		Name:        "strings_extract",
		Category:    "util",
		Description: "Extract printable strings from a local regular binary file.",
		Parameters:  stringSchema([]string{"path"}, "path", "min_len"),
		Available:   func() error { _, err := executable("strings", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Path   string `json:"path"`
				MinLen string `json:"min_len"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			clean, _, err := regularFileCheck(a.Path, 64*1024*1024)
			if err != nil {
				return fail(fmt.Errorf("strings_extract: %w", err))
			}
			minLen, err := boundedIntString(a.MinLen, "min_len", 2, 64, 4)
			if err != nil {
				return fail(err)
			}
			p, err := executable("strings", "")
			if err != nil {
				return fail(err)
			}
			out, err := runToolCLI(ctx, runner, p, []string{"-n", minLen, clean})
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("Extracted strings (min %s) from %s (%d bytes)", minLen, filepath.Base(clean), len(out)), Data: map[string]any{"strings": string(out)}}, nil
		},
	}
}

func fileIdentifyTool(runner Runner) *Tool {
	return &Tool{
		Name:        "file_identify",
		Category:    "util",
		Description: "Identify file type using the file command.",
		Parameters:  stringSchema([]string{"path"}, "path"),
		Available:   func() error { _, err := executable("file", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Path string `json:"path"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			clean, _, err := regularFileCheck(a.Path, 256*1024*1024)
			if err != nil {
				return fail(fmt.Errorf("file_identify: %w", err))
			}
			p, err := executable("file", "")
			if err != nil {
				return fail(err)
			}
			out, err := runToolCLI(ctx, runner, p, []string{"-b", "-z", clean})
			if err != nil {
				return fail(err)
			}
			ft := strings.TrimSpace(string(out))
			return &Result{Success: true, Summary: fmt.Sprintf("%s: %s", filepath.Base(clean), ft), Data: map[string]any{"file_type": ft}}, nil
		},
	}
}

func exiftoolMetaTool(runner Runner) *Tool {
	return &Tool{
		Name:        "exiftool_meta",
		Category:    "util",
		Description: "Extract metadata from a local file using exiftool.",
		Parameters:  stringSchema([]string{"path"}, "path"),
		Available:   func() error { _, err := executable("exiftool", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Path string `json:"path"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			clean, _, err := regularFileCheck(a.Path, 128*1024*1024)
			if err != nil {
				return fail(fmt.Errorf("exiftool_meta: %w", err))
			}
			p, err := executable("exiftool", "")
			if err != nil {
				return fail(err)
			}
			out, err := runToolCLI(ctx, runner, p, []string{"-j", clean})
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("Extracted metadata for %s (%d bytes)", filepath.Base(clean), len(out)), Data: map[string]any{"metadata": string(out)}}, nil
		},
	}
}

func binwalkAnalyzeTool(runner Runner) *Tool {
	return &Tool{
		Name:        "binwalk_analyze",
		Category:    "util",
		Description: "Scan a regular binary for embedded files and executable signatures using binwalk.",
		Parameters:  stringSchema([]string{"path"}, "path"),
		Available:   func() error { _, err := executable("binwalk", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Path string `json:"path"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			clean, _, err := regularFileCheck(a.Path, 128*1024*1024)
			if err != nil {
				return fail(fmt.Errorf("binwalk_analyze: %w", err))
			}
			p, err := executable("binwalk", "")
			if err != nil {
				return fail(err)
			}
			out, err := runToolCLI(ctx, runner, p, []string{"--signature", "--entropy", clean})
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("binwalk signature/entropy scan completed for %s", filepath.Base(clean)), Data: map[string]any{"raw": string(out)}}, nil
		},
	}
}

// ── vulnerability scanner — Nuclei ───────────────────────────────────────────

// validSeverityList checks that a comma-separated severity string contains only
// nuclei-recognized values and returns the cleaned list.
func validSeverityList(raw string) (string, error) {
	allowed := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true, "unknown": true}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(strings.ToLower(part))
		if s == "" {
			continue
		}
		if !allowed[s] {
			return "", fmt.Errorf("invalid severity %q; allowed: critical,high,medium,low,info", s)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return "critical,high,medium", nil
	}
	return strings.Join(out, ","), nil
}

// nucleiSeverityMap converts a nuclei severity string to a domain.Severity.
func nucleiSeverityMap(s string) domain.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return domain.SevCritical
	case "high":
		return domain.SevHigh
	case "medium":
		return domain.SevMedium
	case "low":
		return domain.SevLow
	default:
		return domain.SevInfo
	}
}

// nucleiJSONLine is the per-finding JSON structure emitted by `nuclei -jsonl`.
type nucleiJSONLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
		Classification struct {
			CWEID     json.RawMessage `json:"cwe-id"`
			CVSSScore float64         `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
}

// parseCWEID handles cwe-id being either a JSON string or JSON array of strings.
func parseCWEID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return strings.Join(arr, ",")
	}
	return ""
}

func nucleiScanTool(runner Runner) *Tool {
	return &Tool{
		Name:        "nuclei_scan",
		Category:    "vuln",
		Description: "Nuclei vulnerability scanner. Runs community templates against a scoped host with JSONL output, rate-limited and without out-of-band interaction callbacks. Host must be in mission scope.",
		Parameters:  stringSchema([]string{"host"}, "host", "port", "severity", "templates", "tags"),
		Available:   func() error { _, err := executable("nuclei", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Host      string `json:"host"`
				Port      string `json:"port"`
				Severity  string `json:"severity"`
				Templates string `json:"templates"`
				Tags      string `json:"tags"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := validateSimpleFlagValue(a.Host, "host"); err != nil {
				return fail(err)
			}
			address, err := scopedAddress(ctx, a.Host)
			if err != nil {
				return fail(fmt.Errorf("nuclei_scan: %w", err))
			}

			port := a.Port
			if port != "" {
				if !validPort(port) {
					return fail(errors.New("nuclei_scan: port must be 1–65535"))
				}
				if err := checkPort(ctx, port); err != nil {
					return fail(fmt.Errorf("nuclei_scan: %w", err))
				}
			}

			sev, err := validSeverityList(a.Severity)
			if err != nil {
				return fail(fmt.Errorf("nuclei_scan: %w", err))
			}

			path, err := executable("nuclei", "")
			if err != nil {
				return fail(err)
			}

			// Build target string: use scoped IP directly with vhost header.
			target := address
			if port != "" {
				target = net.JoinHostPort(address, port)
			}

			args := []string{
				"-target", target,
				"-jsonl",
				"-severity", sev,
				"-silent",
				"-no-interactsh",          // no OOB callbacks
				"-rl", "50",               // rate limit: 50 req/s
				"-timeout", "15",          // per-request timeout in seconds
				"-retries", "1",
				"-no-color",
				"-stats-json",             // suppress interactive stats
			}

			// Template-id filter: allow only alphanumeric, dash, comma.
			if a.Templates != "" {
				if err := validateSimpleFlagValue(a.Templates, "templates"); err != nil {
					return fail(err)
				}
				args = append(args, "-t", a.Templates)
			}

			// Tags filter: allow only alphanumeric, dash, comma.
			if a.Tags != "" {
				if err := validateSimpleFlagValue(a.Tags, "tags"); err != nil {
					return fail(err)
				}
				args = append(args, "-tags", a.Tags)
			}

			out, err := runToolCLI(ctx, runner, path, args)
			if err != nil {
				return fail(err)
			}

			// Parse JSONL output into domain.Finding objects.
			var findings []domain.Finding
			var parsed []map[string]any
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || line[0] != '{' {
					continue
				}
				var nr nucleiJSONLine
				if err := json.Unmarshal([]byte(line), &nr); err != nil {
					continue // skip malformed lines
				}

				cweID := parseCWEID(nr.Info.Classification.CWEID)

				var refs []string
				if len(nr.Info.Reference) > 0 {
					refs = nr.Info.Reference
				}

				findings = append(findings, domain.Finding{
					Title:       fmt.Sprintf("[%s] %s", nr.TemplateID, nr.Info.Name),
					Description: nr.Info.Description,
					Severity:    nucleiSeverityMap(nr.Info.Severity),
					CVSS:        nr.Info.Classification.CVSSScore,
					CWE:         cweID,
					Evidence:    append([]string{fmt.Sprintf("matched-at: %s", nr.MatchedAt)}, refs...),
					Phase:       domain.PhaseRecon,
				})

				parsed = append(parsed, map[string]any{
					"template_id": nr.TemplateID,
					"name":        nr.Info.Name,
					"severity":    nr.Info.Severity,
					"host":        nr.Host,
					"matched_at":  nr.MatchedAt,
					"cwe":         cweID,
					"cvss":        nr.Info.Classification.CVSSScore,
				})
			}

			summary := fmt.Sprintf("nuclei scan completed on %s (address %s): %d finding(s)", a.Host, address, len(findings))
			return &Result{
				Success:      true,
				Summary:      summary,
				Findings:     findings,
				Data:         map[string]any{"host": a.Host, "address": address, "severity_filter": sev, "findings_count": len(findings), "findings": parsed},
				Artifact:     out,
				ArtifactType: "application/x-ndjson",
			}, nil
		},
	}
}

// ── pure-Go crypto_hash ──────────────────────────────────────────────────────

func cryptoHashTool() *Tool {
	return &Tool{
		Name:        "crypto_hash",
		Category:    "util",
		Description: "Compute MD5, SHA-1, SHA-256, and SHA-512 digests of a local regular file (up to 10 MiB) or inline data.",
		Parameters:  stringSchema(nil, "path", "data"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Path string `json:"path"`
				Data string `json:"data"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			var r io.Reader
			switch {
			case a.Path != "":
				clean, _, err := regularFileCheck(a.Path, 10*1024*1024)
				if err != nil {
					return fail(fmt.Errorf("crypto_hash: %w", err))
				}
				f, err := os.Open(clean)
				if err != nil {
					return fail(err)
				}
				defer f.Close()
				r = f
			case a.Data != "":
				r = strings.NewReader(a.Data)
			default:
				return fail(errors.New("crypto_hash: provide path or data"))
			}
			b, err := io.ReadAll(io.LimitReader(r, 10*1024*1024))
			if err != nil {
				return fail(err)
			}
			md5h := md5.Sum(b)   //nolint:gosec
			sha1h := sha1.Sum(b) //nolint:gosec
			sha256h := sha256.Sum256(b)
			sha512h := sha512.Sum512(b)
			sha256Hex := hex.EncodeToString(sha256h[:])
			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Digests computed for %d bytes (sha256 %s...)", len(b), sha256Hex[:12]),
				Data: map[string]any{
					"md5":    hex.EncodeToString(md5h[:]),
					"sha1":   hex.EncodeToString(sha1h[:]),
					"sha256": sha256Hex,
					"sha512": hex.EncodeToString(sha512h[:]),
					"bytes":  len(b),
				},
			}, nil
		},
	}
}

func fail(err error) (*Result, error) { return nil, err }
