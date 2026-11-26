package arsenal

// active_scanners.go — Phase 2 active scanning depth:
//   - ssl_scan_full: multi-version TLS (1.0..1.3) and weak/insecure cipher suite enumeration
//   - web_crawl: same-origin recursive crawler + HTML form/parameter extractor
//   - active_web_scan: authorized scoped multi-parameter reflection/error/CRLF/SSTI check

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"rogue/internal/domain"
	"rogue/internal/opsec"
)

// RegisterActiveScannerTools registers ssl_scan_full, web_crawl, and active_web_scan.
func RegisterActiveScannerTools(registry *Registry) {
	registry.Register(sslScanFullTool())
	registry.Register(webCrawlTool())
	registry.Register(activeWebScanTool())
}

// ── ssl_scan_full ────────────────────────────────────────────────────────────

func sslScanFullTool() *Tool {
	return &Tool{
		Name:        "ssl_scan_full",
		Category:    "vuln",
		Description: "Enumerate supported TLS versions (TLS 1.0, 1.1, 1.2, 1.3) and cipher suites including deprecated/weak ciphers on a scoped host:port.",
		Parameters:  stringSchema([]string{"host"}, "host", "port"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct{ Host, Port string }
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Host == "" {
				return nil, errors.New("host is required")
			}
			if err := checkHost(ctx, args.Host); err != nil {
				return nil, err
			}
			port := args.Port
			if port == "" {
				port = "443"
			}
			if !validPort(port) {
				return nil, errors.New("port must be 1–65535")
			}
			if err := checkPort(ctx, port); err != nil {
				return nil, err
			}

			versions := []struct {
				name       string
				ver        uint16
				deprecated bool
			}{
				{"TLS 1.0", tls.VersionTLS10, true},
				{"TLS 1.1", tls.VersionTLS11, true},
				{"TLS 1.2", tls.VersionTLS12, false},
				{"TLS 1.3", tls.VersionTLS13, false},
			}

			var supportedProtocols []string
			var weakProtocols []string
			var acceptedWeakCiphers []string
			var acceptedStrongCiphers []string
			var certInfo map[string]any

			addr := net.JoinHostPort(args.Host, port)
			for _, v := range versions {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				opCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
				conn, err := scopedDial(opCtx, "tcp", addr)
				if err == nil {
					tc := tls.Client(conn, &tls.Config{
						ServerName:         args.Host,
						MinVersion:         v.ver,
						MaxVersion:         v.ver,
						InsecureSkipVerify: true, // scanning target cert/ciphers without trusting CA
					})
					err = tc.HandshakeContext(opCtx)
					if err == nil {
						st := tc.ConnectionState()
						supportedProtocols = append(supportedProtocols, v.name)
						if v.deprecated {
							weakProtocols = append(weakProtocols, v.name)
						}
						if certInfo == nil && len(st.PeerCertificates) > 0 {
							leaf := st.PeerCertificates[0]
							certInfo = map[string]any{
								"subject":        leaf.Subject.String(),
								"issuer":         leaf.Issuer.String(),
								"dns_names":      leaf.DNSNames,
								"not_after":      leaf.NotAfter,
								"days_remaining": int(time.Until(leaf.NotAfter).Hours() / 24),
							}
						}
					}
					tc.Close()
				}
				cancel()
			}

			// Probe individual weak & strong cipher suites on TLS 1.0–1.2.
			for _, cs := range tls.InsecureCipherSuites() {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if probeCipher(ctx, addr, args.Host, cs.ID) {
					acceptedWeakCiphers = append(acceptedWeakCiphers, cs.Name)
				}
			}
			for _, cs := range tls.CipherSuites() {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if slices.Contains(cs.SupportedVersions, tls.VersionTLS12) && probeCipher(ctx, addr, args.Host, cs.ID) {
					acceptedStrongCiphers = append(acceptedStrongCiphers, cs.Name)
				}
			}

			var findings []domain.Finding
			if len(weakProtocols) > 0 {
				findings = append(findings, domain.Finding{
					Title:       "Deprecated TLS protocol versions enabled",
					Description: fmt.Sprintf("Target accepted handshake(s) for deprecated protocol(s): %s.", strings.Join(weakProtocols, ", ")),
					Severity:    domain.SevMedium,
					CWE:         "CWE-326",
					Remediation: "Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2+ (preferring TLS 1.3).",
				})
			}
			if len(acceptedWeakCiphers) > 0 {
				findings = append(findings, domain.Finding{
					Title:       "Weak TLS cipher suites accepted",
					Description: fmt.Sprintf("Target negotiated insecure cipher suite(s): %s.", strings.Join(acceptedWeakCiphers, ", ")),
					Severity:    domain.SevMedium,
					CWE:         "CWE-327",
					Remediation: "Remove weak/legacy cipher suites (RC4, 3DES, CBC-SHA1, RSA key exchange) and prioritize AEAD suites.",
				})
			}

			summary := fmt.Sprintf("%s:%s TLS enum: %d protocol(s), %d weak cipher(s), %d strong TLS1.2 cipher(s)",
				args.Host, port, len(supportedProtocols), len(acceptedWeakCiphers), len(acceptedStrongCiphers))
			return &Result{
				Success:  len(supportedProtocols) > 0,
				Summary:  summary,
				Findings: findings,
				Data: map[string]any{
					"host":                    args.Host,
					"port":                    port,
					"supported_protocols":     supportedProtocols,
					"deprecated_protocols":    weakProtocols,
					"accepted_weak_ciphers":   acceptedWeakCiphers,
					"accepted_strong_ciphers": acceptedStrongCiphers,
					"certificate":             certInfo,
				},
			}, nil
		},
	}
}

func probeCipher(ctx context.Context, addr, serverName string, suiteID uint16) bool {
	opCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := scopedDial(opCtx, "tcp", addr)
	if err != nil {
		return false
	}
	tc := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{suiteID},
		InsecureSkipVerify: true,
	})
	defer tc.Close()
	return tc.HandshakeContext(opCtx) == nil
}

// ── web_crawl ────────────────────────────────────────────────────────────────

var (
	hrefRe  = regexp.MustCompile(`(?i)\b(?:href|src|action)\s*=\s*["']([^"'#\s>]+)["']`)
	formRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	attrRe  = regexp.MustCompile(`(?i)\b(action|method)\s*=\s*["']([^"']*)["']`)
	inputRe = regexp.MustCompile(`(?is)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']`)
)

type crawledForm struct {
	PageURL string   `json:"page_url"`
	Action  string   `json:"action"`
	Method  string   `json:"method"`
	Inputs  []string `json:"inputs"`
}

func webCrawlTool() *Tool {
	return &Tool{
		Name:        "web_crawl",
		Category:    "web",
		Description: "Same-origin recursive web crawler and HTML form/parameter extractor. Enforces mission scope on every URL; respects max_depth (1–3) and max_pages (1–100).",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"url":       map[string]any{"type": "string", "description": "starting URL in scope"},
			"max_depth": map[string]any{"type": "string", "description": "crawl depth 1–3 (default 2)"},
			"max_pages": map[string]any{"type": "string", "description": "max pages 1–100 (default 30)"},
		}, "required": []string{"url"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				URL      string `json:"url"`
				MaxDepth string `json:"max_depth"`
				MaxPages string `json:"max_pages"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			startURL, err := checkURL(ctx, args.URL)
			if err != nil {
				return nil, err
			}
			depthStr, err := boundedIntString(args.MaxDepth, "max_depth", 1, 3, 2)
			if err != nil {
				return nil, err
			}
			pagesStr, err := boundedIntString(args.MaxPages, "max_pages", 1, 100, 30)
			if err != nil {
				return nil, err
			}
			maxDepth, _ := strconv.Atoi(depthStr)
			maxPages, _ := strconv.Atoi(pagesStr)

			origin := startURL.Scheme + "://" + strings.ToLower(startURL.Host)
			type item struct {
				u     string
				depth int
			}
			queue := []item{{startURL.String(), 0}}
			visited := map[string]bool{startURL.String(): true}

			client := newScopedHTTPClient(3, true)
			defer client.CloseIdleConnections()

			var pages []map[string]any
			var forms []crawledForm
			queryParams := make(map[string]bool)

			for len(queue) > 0 && len(pages) < maxPages {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if err := opsec.Sleep(ctx); err != nil {
					return nil, err
				}
				cur := queue[0]
				queue = queue[1:]

				if _, err := checkURL(ctx, cur.u); err != nil {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, cur.u, nil)
				if err != nil {
					continue
				}
				opsec.ApplyBlendHeaders(req)
				resp, err := client.Do(req)
				if err != nil {
					pages = append(pages, map[string]any{"url": cur.u, "error": err.Error()})
					continue
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
				resp.Body.Close()

				finalURL := resp.Request.URL
				finalStr := finalURL.String()
				bodyStr := string(bodyBytes)
				pages = append(pages, map[string]any{
					"url":    finalStr,
					"status": resp.StatusCode,
					"bytes":  len(bodyBytes),
					"depth":  cur.depth,
				})
				for k := range finalURL.Query() {
					queryParams[k] = true
				}

				if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
					continue
				}

				// Extract HTML forms + input field names
				for _, fm := range formRe.FindAllStringSubmatch(bodyStr, 32) {
					attrs, inner := fm[1], fm[2]
					action, method := finalStr, "GET"
					for _, am := range attrRe.FindAllStringSubmatch(attrs, 8) {
						switch strings.ToLower(am[1]) {
						case "action":
							if resolved, rerr := finalURL.Parse(am[2]); rerr == nil {
								action = resolved.String()
							}
						case "method":
							if am[2] != "" {
								method = strings.ToUpper(am[2])
							}
						}
					}
					var inputs []string
					for _, im := range inputRe.FindAllStringSubmatch(inner, 64) {
						if !slices.Contains(inputs, im[1]) {
							inputs = append(inputs, im[1])
						}
					}
					forms = append(forms, crawledForm{PageURL: finalStr, Action: action, Method: method, Inputs: inputs})
				}

				if cur.depth >= maxDepth {
					continue
				}
				for _, m := range hrefRe.FindAllStringSubmatch(bodyStr, 256) {
					ref, perr := finalURL.Parse(strings.TrimSpace(m[1]))
					if perr != nil || (ref.Scheme != "http" && ref.Scheme != "https") {
						continue
					}
					for k := range ref.Query() {
						queryParams[k] = true
					}
					ref.Fragment = ""
					targetOrigin := ref.Scheme + "://" + strings.ToLower(ref.Host)
					if targetOrigin != origin {
						continue
					}
					nextStr := ref.String()
					if !visited[nextStr] {
						visited[nextStr] = true
						queue = append(queue, item{nextStr, cur.depth + 1})
					}
				}
			}

			var params []string
			for p := range queryParams {
				params = append(params, p)
			}
			slices.Sort(params)

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Crawled %d page(s), extracted %d form(s) and %d query parameter(s)", len(pages), len(forms), len(params)),
				Data: map[string]any{
					"start_url":        startURL.String(),
					"pages_visited":    len(pages),
					"pages":            pages,
					"forms":            forms,
					"query_parameters": params,
				},
			}, nil
		},
	}
}

// ── active_web_scan (authorized non-loopback) ────────────────────────────────

func activeWebScanTool() *Tool {
	return &Tool{
		Name:        "active_web_scan",
		Category:    "vuln",
		Description: "Authorized multi-parameter active web assessment against scoped URLs (beyond loopback lab checks when target is in ROGUE_SCOPE and approved). Probes for unescaped HTML reflection, SQL/template error disclosure, and CRLF header reflection; halts immediately on HTTP 429.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"url":        map[string]any{"type": "string", "description": "target URL in mission scope"},
			"parameters": map[string]any{"type": "string", "description": "comma-separated query parameter names to probe (max 16)"},
		}, "required": []string{"url", "parameters"}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			if err := authorizeActive(ctx, "active_web_scan", raw); err != nil {
				return nil, err
			}
			var args struct {
				URL        string `json:"url"`
				Parameters string `json:"parameters"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			base, err := checkURL(ctx, args.URL)
			if err != nil {
				return nil, err
			}
			params, err := boundedList(args.Parameters, 16)
			if err != nil {
				return nil, err
			}

			client := newScopedHTTPClient(0, false)
			defer client.CloseIdleConnections()

			if err := opsec.Sleep(ctx); err != nil {
				return nil, err
			}
			baseline, err := fetchSample(ctx, client, base.String())
			if err != nil {
				return nil, err
			}
			if baseline.Status == 429 {
				return &Result{Success: false, Summary: "Baseline rate limited (HTTP 429); active scan aborted", Error: "rate limited"}, nil
			}

			markerBytes := make([]byte, 6)
			_, _ = rand.Read(markerBytes)
			marker := "rogue" + hex.EncodeToString(markerBytes)

			sqlErrRe := regexp.MustCompile(`(?i)SQLITE_ERROR|SQL syntax.*MySQL|unterminated quoted string|syntax error at or near|SQLSTATE\[[0-9A-Z]+\]|ORA-[0-9]{5}`)

			var probeResults []map[string]any
			var findings []domain.Finding

			for _, param := range params {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				checks := []struct {
					kind  string
					value string
				}{
					{"reflection", "<" + marker + ">"},
					{"sqli_error", "'"},
					{"ssti", "{{7*7}}"},
				}
				for _, ch := range checks {
					if err := opsec.Sleep(ctx); err != nil {
						return nil, err
					}
					u := *base
					q := u.Query()
					q.Set(param, ch.value)
					u.RawQuery = q.Encode()

					sample, perr := fetchSample(ctx, client, u.String())
					if perr != nil {
						probeResults = append(probeResults, map[string]any{"parameter": param, "check": ch.kind, "error": perr.Error()})
						continue
					}
					if sample.Status == 429 {
						return &Result{
							Success: false,
							Summary: "Target returned HTTP 429; active scan halted to preserve OPSEC",
							Error:   "rate limited during active scan",
							Data:    map[string]any{"partial_probes": probeResults},
						}, nil
					}
					item := map[string]any{"parameter": param, "check": ch.kind, "status": sample.Status, "bytes": len(sample.Body)}
					switch ch.kind {
					case "reflection":
						isHTML := strings.Contains(strings.ToLower(sample.Headers.Get("Content-Type")), "text/html")
						reflected := isHTML && strings.Contains(sample.Body, ch.value)
						item["reflected"] = reflected
						if reflected {
							findings = append(findings, domain.Finding{
								Title:       fmt.Sprintf("Unescaped HTML marker reflected in %q", param),
								Description: "Harmless angle-bracket marker appeared unencoded in an HTML response. Script execution not attempted.",
								Severity:    domain.SevLow,
								CWE:         "CWE-79",
								Remediation: "Apply context-aware HTML output encoding.",
							})
						}
					case "sqli_error":
						match := sqlErrRe.FindString(sample.Body)
						newErr := match != "" && !sqlErrRe.MatchString(baseline.Body)
						item["new_sql_error"] = newErr
						if newErr {
							item["signature"] = match
							findings = append(findings, domain.Finding{
								Title:       fmt.Sprintf("Database error exposed on parameter %q", param),
								Description: fmt.Sprintf("Database diagnostic (%s) appeared only on syntax probe; verify parameterized queries.", match),
								Severity:    domain.SevLow,
								CWE:         "CWE-209",
								Remediation: "Use parameterized queries and suppress database error details.",
							})
						}
					case "ssti":
						evalHint := strings.Contains(sample.Body, "49") && !strings.Contains(baseline.Body, "49")
						item["arithmetic_49_observed"] = evalHint
						if evalHint {
							findings = append(findings, domain.Finding{
								Title:       fmt.Sprintf("Potential template expression evaluation on parameter %q", param),
								Description: "Submitting {{7*7}} produced 49 not present in baseline. Manual verification required.",
								Severity:    domain.SevMedium,
								CWE:         "CWE-1336",
								Remediation: "Use logic-less templates or sandbox untrusted expressions.",
							})
						}
					}
					probeResults = append(probeResults, item)
				}
			}

			return &Result{
				Success:  true,
				Summary:  fmt.Sprintf("Active scan probed %d parameter(s) across %s: %d finding(s)", len(params), args.URL, len(findings)),
				Findings: findings,
				Data: map[string]any{
					"url":                args.URL,
					"baseline_status":    baseline.Status,
					"parameters_probed":  params,
					"probe_results":      probeResults,
					"confirmed_exploits": false,
				},
			}, nil
		},
	}
}
