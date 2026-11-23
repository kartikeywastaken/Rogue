package arsenal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"rogue/internal/domain"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// RegisterReconTools adds the built-in reconnaissance tools to the registry.
func RegisterReconTools(r *Registry) {
	r.Register(dnsLookupTool())
	r.Register(portScanTool())
	r.Register(httpRequestTool())
	r.Register(headerAnalysisTool())
}

// ── dns_lookup ───────────────────────────────────────────────────────────────

func dnsLookupTool() *Tool {
	return &Tool{
		Name:        "dns_lookup",
		Category:    "recon",
		Description: "Resolve DNS records for a hostname. Returns records of the requested type (A, AAAA, MX, NS, TXT, CNAME).",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":        map[string]any{"type": "string", "description": "Hostname or domain to resolve"},
				"record_type": map[string]any{"type": "string", "enum": []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME"}, "description": "DNS record type (default: A)"},
			},
			"required": []string{"host"},
		},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Host       string `json:"host"`
				RecordType string `json:"record_type"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, fmt.Errorf("parse args: %w", err)
			}
			if args.Host == "" {
				return nil, fmt.Errorf("host is required")
			}
			if err := checkHost(ctx, args.Host); err != nil {
				return nil, err
			}
			if args.RecordType == "" {
				args.RecordType = "A"
			}
			resolver := &net.Resolver{}
			var records []string
			var err error
			switch strings.ToUpper(args.RecordType) {
			case "A", "AAAA":
				var ips []net.IP
				network := "ip4"
				if strings.EqualFold(args.RecordType, "AAAA") {
					network = "ip6"
				}
				ips, err = resolver.LookupIP(ctx, network, args.Host)
				for _, ip := range ips {
					records = append(records, ip.String())
				}
			case "MX":
				var mxs []*net.MX
				mxs, err = resolver.LookupMX(ctx, args.Host)
				for _, mx := range mxs {
					records = append(records, fmt.Sprintf("%s (priority %d)", mx.Host, mx.Pref))
				}
			case "NS":
				var nss []*net.NS
				nss, err = resolver.LookupNS(ctx, args.Host)
				for _, ns := range nss {
					records = append(records, ns.Host)
				}
			case "TXT":
				records, err = resolver.LookupTXT(ctx, args.Host)
			case "CNAME":
				var cname string
				cname, err = resolver.LookupCNAME(ctx, args.Host)
				if cname != "" {
					records = append(records, cname)
				}
			default:
				return nil, fmt.Errorf("unsupported record type %q", args.RecordType)
			}
			if err != nil {
				return &Result{Success: false, Summary: err.Error()}, nil
			}
			summary := fmt.Sprintf("%s %s: %d records", args.Host, args.RecordType, len(records))
			return &Result{
				Success: true,
				Data:    map[string]any{"host": args.Host, "type": args.RecordType, "records": records},
				Summary: summary,
			}, nil
		},
	}
}

// ── port_scan ────────────────────────────────────────────────────────────────

var defaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389, 5432,
	5900, 6379, 8080, 8443, 8888, 9090, 27017,
}

func portScanTool() *Tool {
	return &Tool{
		Name:        "port_scan",
		Category:    "recon",
		Description: "TCP connect scan. Tests which ports are open on a target host. Defaults to common ports if none specified.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":  map[string]any{"type": "string", "description": "Target host or IP address"},
				"ports": map[string]any{"type": "string", "description": "Comma-separated port numbers (e.g. \"80,443,8080\"). Defaults to 26 common ports."},
			},
			"required": []string{"host"},
		},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Host  string `json:"host"`
				Ports string `json:"ports"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, fmt.Errorf("parse args: %w", err)
			}
			if args.Host == "" {
				return nil, fmt.Errorf("host is required")
			}
			if err := checkHost(ctx, args.Host); err != nil {
				return nil, err
			}

			ports := defaultPorts
			if args.Ports != "" {
				ports = nil
				for _, s := range strings.Split(args.Ports, ",") {
					s = strings.TrimSpace(s)
					p, err := strconv.Atoi(s)
					if err != nil || p < 1 || p > 65535 {
						return nil, fmt.Errorf("invalid port %q", s)
					}
					if !containsPort(ports, p) {
						ports = append(ports, p)
					}
				}
			}

			type portResult struct {
				Port  int
				State string
			}
			results := make([]portResult, len(ports))
			var wg sync.WaitGroup
			// A fixed worker pool bounds goroutines as well as live sockets.
			jobs := make(chan int)
			for range min(32, len(ports)) {
				wg.Go(func() {
					for idx := range jobs {
						if ctx.Err() != nil {
							return
						}
						port := ports[idx]
						addr := net.JoinHostPort(args.Host, strconv.Itoa(port))
						conn, err := scopedDial(ctx, "tcp", addr)
						if err == nil {
							conn.Close()
							results[idx] = portResult{Port: port, State: "open"}
						} else {
							state := "error"
							var ne net.Error
							if errors.As(err, &ne) && ne.Timeout() {
								state = "timeout"
							}
							// A refusal is closed; resolution, policy, and routing errors are not.
							if errors.Is(err, syscall.ECONNREFUSED) {
								state = "closed"
							}
							results[idx] = portResult{Port: port, State: state}
						}
					}
				})
			}
		feed:
			for i := range ports {
				select {
				case jobs <- i:
				case <-ctx.Done():
					break feed
				}
			}
			close(jobs)
			wg.Wait()
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			var open, closed, timedOut, failed []int
			for _, r := range results {
				switch r.State {
				case "open":
					open = append(open, r.Port)
				case "closed":
					closed = append(closed, r.Port)
				case "timeout":
					timedOut = append(timedOut, r.Port)
				default:
					failed = append(failed, r.Port)
				}
			}
			sort.Ints(open)
			sort.Ints(closed)

			summary := fmt.Sprintf("%s: %d open, %d closed, %d timed out, %d errors", args.Host, len(open), len(closed), len(timedOut), len(failed))
			if len(open) > 0 {
				ps := make([]string, len(open))
				for i, p := range open {
					ps[i] = strconv.Itoa(p)
				}
				summary += " · open: " + strings.Join(ps, ", ")
			}
			return &Result{
				Success: len(failed) == 0 && len(timedOut) == 0,
				Data:    map[string]any{"host": args.Host, "open_ports": open, "closed_ports": closed, "timed_out_ports": timedOut, "error_ports": failed},
				Summary: summary,
			}, nil
		},
	}
}

// ── http_request ─────────────────────────────────────────────────────────────

func httpRequestTool() *Tool {
	return &Tool{
		Name:        "http_request",
		Category:    "recon",
		Description: "Make an HTTP/HTTPS request and return the status code, response headers, and a truncated body.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":    map[string]any{"type": "string", "description": "Full URL to request"},
				"method": map[string]any{"type": "string", "enum": []string{"GET", "HEAD", "POST", "OPTIONS"}, "description": "HTTP method (default: GET)"},
			},
			"required": []string{"url"},
		},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				URL    string `json:"url"`
				Method string `json:"method"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, fmt.Errorf("parse args: %w", err)
			}
			if args.URL == "" {
				return nil, fmt.Errorf("url is required")
			}
			if args.Method == "" {
				args.Method = "GET"
			}
			if _, err := checkURL(ctx, args.URL); err != nil {
				return nil, err
			}
			client := scopedHTTPClient()
			defer client.CloseIdleConnections()

			req, err := http.NewRequestWithContext(ctx, args.Method, args.URL, nil)
			if err != nil {
				return nil, fmt.Errorf("create request: %w", err)
			}
			req.Header.Set("User-Agent", "ROGUE/1.0 SecurityScanner")

			resp, err := client.Do(req)
			if err != nil {
				return &Result{Success: false, Summary: err.Error()}, nil
			}
			defer resp.Body.Close()

			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
			if err != nil {
				return nil, fmt.Errorf("read response: %w", err)
			}
			truncated := len(bodyBytes) > 4096
			if truncated {
				bodyBytes = bodyBytes[:4096]
			}
			headers := make(map[string]string)
			for k := range resp.Header {
				headers[k] = resp.Header.Get(k)
			}

			summary := fmt.Sprintf("%s %s → %d %s (%d bytes)",
				args.Method, args.URL, resp.StatusCode, resp.Status, len(bodyBytes))
			return &Result{
				Success: true,
				Data: map[string]any{
					"status_code": resp.StatusCode,
					"status":      resp.Status,
					"headers":     headers,
					"body":        string(bodyBytes),
					"truncated":   truncated,
				},
				Summary: summary,
			}, nil
		},
	}
}

// ── header_analysis ──────────────────────────────────────────────────────────

func headerAnalysisTool() *Tool {
	secHeaders := []struct {
		name string
		desc string
	}{
		{"Strict-Transport-Security", "HSTS — prevents protocol downgrade"},
		{"Content-Security-Policy", "CSP — prevents XSS and injection"},
		{"X-Content-Type-Options", "Prevents MIME sniffing"},
		{"X-Frame-Options", "Clickjacking protection"},
		{"Referrer-Policy", "Controls referrer leakage"},
		{"Permissions-Policy", "Controls browser features"},
		{"Cross-Origin-Opener-Policy", "COOP — isolates browsing context"},
		{"Cross-Origin-Resource-Policy", "CORP — restricts cross-origin loads"},
	}
	return &Tool{
		Name:        "header_analysis",
		Category:    "recon",
		Description: "Analyze HTTP response headers for security misconfigurations. Fetches the URL and checks for missing security headers.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url": map[string]any{"type": "string", "description": "URL to analyze"},
			},
			"required": []string{"url"},
		},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, fmt.Errorf("parse args: %w", err)
			}
			if args.URL == "" {
				return nil, fmt.Errorf("url is required")
			}

			if _, err := checkURL(ctx, args.URL); err != nil {
				return nil, err
			}
			client := scopedHTTPClient()
			defer client.CloseIdleConnections()
			req, err := http.NewRequestWithContext(ctx, "HEAD", args.URL, nil)
			if err != nil {
				return nil, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return &Result{Success: false, Summary: err.Error()}, nil
			}
			resp.Body.Close()

			type finding struct {
				Header  string `json:"header"`
				Present bool   `json:"present"`
				Value   string `json:"value,omitempty"`
				Note    string `json:"note"`
			}
			var findings []finding
			var assessments []domain.Finding
			present, missing := 0, 0
			for _, h := range secHeaders {
				v := resp.Header.Get(h.name)
				if v != "" {
					present++
					findings = append(findings, finding{Header: h.name, Present: true, Value: v, Note: h.desc})
				} else {
					missing++
					findings = append(findings, finding{Header: h.name, Present: false, Note: h.desc + " — MISSING"})
					assessments = append(assessments, domain.Finding{Title: "Missing " + h.name, Description: "Header absent in HEAD response; relevance requires application-specific review.", Severity: domain.SevInfo, TargetID: args.URL, Phase: domain.PhaseRecon, Remediation: "Review whether this header applies to this service and configure it where appropriate."})
				}
			}

			score := float64(present) / float64(present+missing) * 100
			summary := fmt.Sprintf("%s: %.0f%% (%d/%d security headers present)", args.URL, score, present, present+missing)
			return &Result{
				Success:  true,
				Data:     map[string]any{"url": args.URL, "score_pct": score, "findings": findings},
				Summary:  summary,
				Findings: assessments,
			}, nil
		},
	}
}

func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
