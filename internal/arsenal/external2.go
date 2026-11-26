package arsenal

// extended2.go — Phase 2 external CLI wrappers.
// Follows the exact Tool pattern from external.go:
//   - Description, Parameters (JSON Schema), Execute func(ctx, json.RawMessage)(*Result,error)
//   - Env stripped to PATH, LANG, LC_ALL
//   - stdout capped at 2 MiB via ProcessRunner
//   - Network tools call checkURL or checkHost before execution
//   - Lab-only tools call labURL (requires ROGUE_LAB=true + loopback IP)

import (
	"context"
	"crypto/md5"  //nolint:gosec
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// RegisterExtendedTools adds Phase 2 external CLI wrappers to the registry.
func RegisterExtendedTools(registry *Registry, options ExternalOptions) {
	runner := options.Runner
	if runner == nil {
		runner = ProcessRunner{}
	}

	// ── dirb ─────────────────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "dirb_scan",
		Category:    "web",
		Description: "Directory brute-force with dirb. URL must be in mission scope.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"target_url": map[string]any{"type": "string", "description": "URL to scan"},
			"wordlist":   map[string]any{"type": "string", "description": "(optional) wordlist path"},
		}, "required": []string{"target_url"}},
		Available: func() error { _, err := executable("dirb", ""); return err },
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
			args := []string{a.TargetURL, "-o", "/dev/stdout", "-r", "-S"}
			if a.Wordlist != "" {
				args = []string{a.TargetURL, a.Wordlist, "-o", "/dev/stdout", "-r", "-S"}
			}
			out, _ := runner.Run(ctx, path, args)
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── ffuf ─────────────────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "ffuf_scan",
		Category:    "web",
		Description: "Fast web fuzzer. target_url must contain FUZZ. URL must be in scope.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"target_url":  map[string]any{"type": "string", "description": "URL with FUZZ placeholder"},
			"wordlist":    map[string]any{"type": "string", "description": "wordlist path"},
			"hide_status": map[string]any{"type": "string", "description": "comma-separated status codes to hide e.g. 404"},
		}, "required": []string{"target_url", "wordlist"}},
		Available: func() error { _, err := executable("ffuf", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				TargetURL  string `json:"target_url"`
				Wordlist   string `json:"wordlist"`
				HideStatus string `json:"hide_status"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			scopeURL := strings.ReplaceAll(a.TargetURL, "FUZZ", "index")
			if _, err := checkURL(ctx, scopeURL); err != nil {
				return fail(fmt.Errorf("ffuf_scan: %w", err))
			}
			path, err := executable("ffuf", "")
			if err != nil {
				return fail(err)
			}
			args := []string{"-u", a.TargetURL, "-w", a.Wordlist, "-o", "/dev/stdout", "-of", "json", "-s"}
			if a.HideStatus != "" {
				args = append(args, "-fc", a.HideStatus)
			}
			out, _ := runner.Run(ctx, path, args)
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── gobuster ──────────────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "gobuster_scan",
		Category:    "web",
		Description: "Directory/file enumeration with gobuster. URL must be in scope.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"target_url": map[string]any{"type": "string", "description": "URL to scan"},
			"wordlist":   map[string]any{"type": "string", "description": "wordlist path"},
			"extensions": map[string]any{"type": "string", "description": "file extensions e.g. php,html"},
		}, "required": []string{"target_url", "wordlist"}},
		Available: func() error { _, err := executable("gobuster", ""); return err },
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
			path, err := executable("gobuster", "")
			if err != nil {
				return fail(err)
			}
			args := []string{"dir", "-u", a.TargetURL, "-w", a.Wordlist, "-q", "--no-progress"}
			if a.Extensions != "" {
				args = append(args, "-x", a.Extensions)
			}
			out, _ := runner.Run(ctx, path, args)
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── nikto ────────────────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "nikto_scan",
		Category:    "vuln",
		Description: "Nikto web server vulnerability scanner. Host must be in mission scope.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"host": map[string]any{"type": "string", "description": "target hostname or IP"},
			"port": map[string]any{"type": "string", "description": "(optional) port number"},
		}, "required": []string{"host"}},
		Available: func() error { _, err := executable("nikto", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Host string `json:"host"`
				Port string `json:"port"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := checkHost(ctx, a.Host); err != nil {
				return fail(fmt.Errorf("nikto_scan: %w", err))
			}
			path, err := executable("nikto", "")
			if err != nil {
				return fail(err)
			}
			args := []string{"-h", a.Host, "-Format", "txt", "-nointeractive", "-Tuning", "123457890abc"}
			if a.Port != "" {
				args = append(args, "-port", a.Port)
			}
			out, _ := runner.Run(ctx, path, args)
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── sqlmap (lab only) ─────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "sqlmap_probe",
		Category:    "vuln",
		LabOnly:     true,
		Description: "SQLMap injection probe. Lab-only: requires ROGUE_LAB=true and loopback target.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"target_url": map[string]any{"type": "string", "description": "URL to probe (must be loopback)"},
			"level":      map[string]any{"type": "string", "description": "1-5 (default 1)"},
			"risk":       map[string]any{"type": "string", "description": "1-3 (default 1)"},
		}, "required": []string{"target_url"}},
		Available: func() error { _, err := executable("sqlmap", ""); return err },
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
			path, err := executable("sqlmap", "")
			if err != nil {
				return fail(err)
			}
			level, risk := "1", "1"
			if a.Level != "" {
				level = a.Level
			}
			if a.Risk != "" {
				risk = a.Risk
			}
			args := []string{"-u", a.TargetURL, "--batch", "--level=" + level, "--risk=" + risk, "--output-dir=/tmp/rogue-sqlmap"}
			out, _ := runner.Run(ctx, path, args)
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── hydra (lab only) ─────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "hydra_probe",
		Category:    "auth",
		LabOnly:     true,
		Description: "Hydra credential probe. Lab-only: requires ROGUE_LAB=true and loopback target.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"service": map[string]any{"type": "string", "description": "protocol e.g. http-post-form, ssh, ftp"},
			"host":    map[string]any{"type": "string", "description": "loopback host"},
			"user":    map[string]any{"type": "string", "description": "username"},
			"pass":    map[string]any{"type": "string", "description": "password"},
		}, "required": []string{"service", "host", "user", "pass"}},
		Available:     func() error { _, err := executable("hydra", ""); return err },
		SensitiveArgs: []string{"pass"},
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
			if _, err := labURL(ctx, "http://"+a.Host); err != nil {
				return fail(fmt.Errorf("hydra_probe: %w", err))
			}
			path, err := executable("hydra", "")
			if err != nil {
				return fail(err)
			}
			out, _ := runner.Run(ctx, path, []string{"-l", a.User, "-p", a.Pass, a.Host, a.Service})
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── host lookup ───────────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "host_lookup",
		Category:    "recon",
		Description: "DNS record lookup via the host command. Host must be in scope.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"hostname": map[string]any{"type": "string", "description": "target hostname"},
			"type":     map[string]any{"type": "string", "description": "record type: A, AAAA, MX, NS, TXT, CNAME (default A)"},
		}, "required": []string{"hostname"}},
		Available: func() error { _, err := executable("host", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Hostname string `json:"hostname"`
				Type     string `json:"type"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
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
			out, _ := runner.Run(ctx, path, []string{"-t", recType, a.Hostname})
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── wget fetch ───────────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "wget_fetch",
		Category:    "recon",
		Description: "Fetch a URL with wget. Output is captured, not written to disk. Scope enforced.",
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
			if _, err := checkURL(ctx, a.URL); err != nil {
				return fail(fmt.Errorf("wget_fetch: %w", err))
			}
			path, err := executable("wget", "")
			if err != nil {
				return fail(err)
			}
			args := []string{"-q", "-O", "-", "--timeout=15", "--tries=1", a.URL}
			if a.HeadersOnly {
				args = []string{"-q", "--server-response", "--spider", "--timeout=15", a.URL}
			}
			out, _ := runner.Run(ctx, path, args)
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── openssl TLS scan ──────────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "openssl_scan",
		Category:    "vuln",
		Description: "Enumerate TLS configuration and certificate info via openssl s_client. Host must be in scope.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"host": map[string]any{"type": "string", "description": "target hostname"},
			"port": map[string]any{"type": "string", "description": "port (default 443)"},
		}, "required": []string{"host"}},
		Available: func() error { _, err := executable("openssl", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Host string `json:"host"`
				Port string `json:"port"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := checkHost(ctx, a.Host); err != nil {
				return fail(fmt.Errorf("openssl_scan: %w", err))
			}
			port := "443"
			if a.Port != "" {
				port = a.Port
			}
			path, err := executable("openssl", "")
			if err != nil {
				return fail(err)
			}
			addr := a.Host + ":" + port
			out, _ := runner.Run(ctx, path, []string{"s_client", "-connect", addr, "-brief"})
			return ok(map[string]any{"raw": string(out), "addr": addr}), nil
		},
	})

	// ── forensics / binary utilities ─────────────────────────────────────────

	registry.Register(&Tool{
		Name:        "xxd_dump",
		Category:    "util",
		Description: "Hex dump of a local file (first 4096 bytes).",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "absolute path to the file"},
		}, "required": []string{"path"}},
		Available: func() error { _, err := executable("xxd", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Path string `json:"path"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			p, err := executable("xxd", "")
			if err != nil {
				return fail(err)
			}
			out, _ := runner.Run(ctx, p, []string{"-l", "4096", a.Path})
			return ok(map[string]any{"hex_dump": string(out)}), nil
		},
	})

	registry.Register(&Tool{
		Name:        "strings_extract",
		Category:    "util",
		Description: "Extract printable strings from a local binary file.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path":    map[string]any{"type": "string", "description": "absolute path to the file"},
			"min_len": map[string]any{"type": "string", "description": "minimum string length (default 4)"},
		}, "required": []string{"path"}},
		Available: func() error { _, err := executable("strings", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Path   string `json:"path"`
				MinLen string `json:"min_len"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			minLen := "4"
			if a.MinLen != "" {
				minLen = a.MinLen
			}
			p, err := executable("strings", "")
			if err != nil {
				return fail(err)
			}
			out, _ := runner.Run(ctx, p, []string{"-n", minLen, a.Path})
			return ok(map[string]any{"strings": string(out)}), nil
		},
	})

	registry.Register(&Tool{
		Name:        "file_identify",
		Category:    "util",
		Description: "Identify file type using the file command.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "absolute path to the file"},
		}, "required": []string{"path"}},
		Available: func() error { _, err := executable("file", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Path string `json:"path"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			p, err := executable("file", "")
			if err != nil {
				return fail(err)
			}
			out, _ := runner.Run(ctx, p, []string{"-b", "-z", a.Path})
			return ok(map[string]any{"file_type": strings.TrimSpace(string(out))}), nil
		},
	})

	registry.Register(&Tool{
		Name:        "exiftool_meta",
		Category:    "util",
		Description: "Extract metadata from a local file using exiftool.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "absolute path to the file"},
		}, "required": []string{"path"}},
		Available: func() error { _, err := executable("exiftool", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Path string `json:"path"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			p, err := executable("exiftool", "")
			if err != nil {
				return fail(err)
			}
			out, _ := runner.Run(ctx, p, []string{"-j", a.Path})
			return ok(map[string]any{"metadata": string(out)}), nil
		},
	})

	registry.Register(&Tool{
		Name:        "binwalk_analyze",
		Category:    "util",
		Description: "Scan a binary for embedded files and executable code using binwalk.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "absolute path to the file"},
		}, "required": []string{"path"}},
		Available: func() error { _, err := executable("binwalk", ""); return err },
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Path string `json:"path"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			p, err := executable("binwalk", "")
			if err != nil {
				return fail(err)
			}
			out, _ := runner.Run(ctx, p, []string{"--signature", "--entropy", a.Path})
			return ok(map[string]any{"raw": string(out)}), nil
		},
	})

	// ── crypto_hash — pure Go ─────────────────────────────────────────────────
	registry.Register(&Tool{
		Name:        "crypto_hash",
		Category:    "util",
		Description: "Compute MD5, SHA-1, SHA-256, and SHA-512 of a local file or inline data.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "file path (mutually exclusive with data)"},
			"data": map[string]any{"type": "string", "description": "inline string data (mutually exclusive with path)"},
		}},
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
				f, err := os.Open(filepath.Clean(a.Path))
				if err != nil {
					return fail(err)
				}
				defer f.Close()
				r = f
			case a.Data != "":
				r = strings.NewReader(a.Data)
			default:
				return fail(fmt.Errorf("crypto_hash: provide path or data"))
			}
			b, err := io.ReadAll(io.LimitReader(r, 10*1024*1024))
			if err != nil {
				return fail(err)
			}
			md5h := md5.Sum(b)   //nolint:gosec
			sha1h := sha1.Sum(b) //nolint:gosec
			sha256h := sha256.Sum256(b)
			sha512h := sha512.Sum512(b)
			return ok(map[string]any{
				"md5":    hex.EncodeToString(md5h[:]),
				"sha1":   hex.EncodeToString(sha1h[:]),
				"sha256": hex.EncodeToString(sha256h[:]),
				"sha512": hex.EncodeToString(sha512h[:]),
				"bytes":  len(b),
			}), nil
		},
	})

	// ── solidity_audit — pure Go static analysis ──────────────────────────────
	registry.Register(&Tool{
		Name:        "solidity_audit",
		Category:    "util",
		Description: "Static regex audit of Solidity source for common vulnerability patterns. Operates on a local file path or inline code. Analysis only.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "path to .sol file"},
			"code": map[string]any{"type": "string", "description": "inline Solidity source"},
		}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct {
				Path string `json:"path"`
				Code string `json:"code"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			var src string
			switch {
			case a.Path != "":
				b, err := os.ReadFile(filepath.Clean(a.Path))
				if err != nil {
					return fail(err)
				}
				src = string(b)
			case a.Code != "":
				src = a.Code
			default:
				return fail(fmt.Errorf("solidity_audit: provide path or code"))
			}
			findings := solidityAnalyze(src)
			return ok(map[string]any{
				"total_findings": len(findings),
				"findings":       findings,
				"note":           "Static pattern analysis only — does not confirm exploitability. Manual review required.",
			}), nil
		},
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func ok(data any) *Result  { return &Result{Success: true, Data: data} }
func fail(err error) (*Result, error) { return nil, err }

// ── Solidity static analysis ──────────────────────────────────────────────────

type solidityFinding struct {
	Rule    string `json:"rule"`
	Detail  string `json:"detail"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

var solidityRules = []struct {
	name    string
	pattern *regexp.Regexp
	detail  string
}{
	{"reentrancy", regexp.MustCompile(`(?i)call\s*\{`), "Potential reentrancy: external call before state update"},
	{"tx_origin_auth", regexp.MustCompile(`\btx\.origin\b`), "tx.origin used for auth — use msg.sender instead"},
	{"block_timestamp", regexp.MustCompile(`\bblock\.timestamp\b`), "block.timestamp dependence: miners can manipulate within ~15s"},
	{"unchecked_call", regexp.MustCompile(`\.call\s*\(`), "Low-level .call() — return value must be checked"},
	{"selfdestruct", regexp.MustCompile(`\bselfdestruct\b|\bsuicide\b`), "selfdestruct present — high-risk fund-drain vector"},
	{"assembly", regexp.MustCompile(`\bassembly\b\s*\{`), "Inline assembly — requires careful review"},
	{"hardcoded_addr", regexp.MustCompile(`0x[0-9a-fA-F]{40}`), "Hardcoded Ethereum address — verify intent"},
	{"overflow_check", regexp.MustCompile(`\bunchecked\b\s*\{`), "unchecked block disables arithmetic overflow protection"},
	{"delegatecall", regexp.MustCompile(`\.delegatecall\s*\(`), "delegatecall — storage layout must match"},
}

func solidityAnalyze(src string) []solidityFinding {
	lines := strings.Split(src, "\n")
	var findings []solidityFinding
	for _, rule := range solidityRules {
		for i, line := range lines {
			if rule.pattern.MatchString(line) {
				snippet := strings.TrimFunc(line, unicode.IsSpace)
				if len(snippet) > 120 {
					snippet = snippet[:120] + "..."
				}
				findings = append(findings, solidityFinding{
					Rule:    rule.name,
					Detail:  rule.detail,
					Line:    i + 1,
					Snippet: snippet,
				})
			}
		}
	}
	return findings
}
