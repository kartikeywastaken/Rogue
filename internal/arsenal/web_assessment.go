package arsenal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"rogue/internal/domain"
)

func RegisterWebAssessmentTools(registry *Registry) {
	registry.Register(whoisTool())
	registry.Register(queryProbe(false))
	registry.Register(queryProbe(true))
	password := passwordTool()
	password.SensitiveArgs = []string{"password"}
	registry.Register(password)
}

func whoisTool() *Tool {
	return &Tool{Name: "whois_lookup", Category: "recon", Description: "Query the fixed IANA WHOIS service for a scoped domain. Referrals are reported, never followed automatically.", Parameters: stringSchema([]string{"host"}, "host"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Host string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if err := checkHost(ctx, args.Host); err != nil {
			return nil, err
		}
		if len(args.Host) > 253 || strings.ContainsAny(args.Host, "\r\n /:@\\") || net.ParseIP(args.Host) != nil {
			return nil, errors.New("WHOIS query must be a domain name")
		}
		operation, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		connection, err := (&net.Dialer{}).DialContext(operation, "tcp", "whois.iana.org:43")
		if err != nil {
			return nil, err
		}
		defer connection.Close()
		deadline, _ := operation.Deadline()
		_ = connection.SetDeadline(deadline)
		stop := context.AfterFunc(operation, func() { connection.Close() })
		defer stop()
		if _, err = io.WriteString(connection, args.Host+"\r\n"); err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(connection, 16384))
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, errors.New("WHOIS service returned no data")
		}
		return &Result{Success: true, Summary: "IANA WHOIS response received; referrals are not ownership verification", Data: map[string]any{"source": "whois.iana.org", "text": string(data), "possibly_truncated": len(data) == 16384}}, nil
	}}
}

func queryProbe(sql bool) *Tool {
	name, description := "xss_scan", "Check whether a harmless HTML-shaped marker is reflected into an HTML response. Reflection is not proof of JavaScript execution."
	if sql {
		name = "sqli_scan"
		description = "Compare a baseline GET with one syntax probe for newly exposed database errors. Reports disclosure evidence, never automatically confirms SQL injection."
	}
	return &Tool{Name: name, Category: "vuln", LabOnly: true, Description: description + " Loopback lab only; exact action approval required.", Parameters: stringSchema([]string{"url", "parameter"}, "url", "parameter"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ URL, Parameter string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		base, err := labURL(ctx, args.URL)
		if err != nil {
			return nil, err
		}
		if args.Parameter == "" || len(args.Parameter) > 64 {
			return nil, errors.New("query parameter required (maximum 64 bytes)")
		}
		client := scopedHTTPClient()
		defer client.CloseIdleConnections()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		baseline, err := fetchSample(ctx, client, base.String())
		if err != nil {
			return nil, err
		}
		if baseline.Status == 429 {
			return &Result{Success: false, Summary: "Baseline rate limited; active probe skipped", Error: "target rate limited the baseline request", Data: map[string]any{"status": 429}}, nil
		}
		markerBytes := make([]byte, 8)
		if _, err = rand.Read(markerBytes); err != nil {
			return nil, err
		}
		marker := "<rogue-" + hex.EncodeToString(markerBytes) + ">"
		query := base.Query()
		value := marker
		if sql {
			value = query.Get(args.Parameter) + "'"
		}
		query.Set(args.Parameter, value)
		base.RawQuery = query.Encode()
		probe, err := fetchSample(ctx, client, base.String())
		if err != nil {
			return nil, err
		}
		data := map[string]any{"status": probe.Status, "baseline_status": baseline.Status, "probe_status": probe.Status, "url": args.URL, "parameter": args.Parameter, "confirmed_exploit": false}
		result := &Result{Success: true, Data: data, Summary: "Probe completed; no confirmed exploit"}
		if sql {
			pattern := regexp.MustCompile(`(?i)SQLITE_ERROR|SQL syntax.*MySQL|unterminated quoted string|syntax error at or near|SQLSTATE\[[0-9A-Z]+\]|ORA-[0-9]{5}`)
			match := pattern.FindString(probe.Body)
			data["new_database_error"] = match != "" && !pattern.MatchString(baseline.Body)
			if data["new_database_error"] == true {
				data["error_signature"] = match
				result.Summary = "New database error exposed by syntax probe; injection exploitability unverified"
				result.Findings = []domain.Finding{{Title: "Database error disclosed after query syntax probe", Description: "A database error signature appeared only after a single quoted query value. This establishes error disclosure, not executable SQL injection.", Severity: domain.SevLow, CWE: "CWE-209", Remediation: "Use parameterized queries and suppress database diagnostics in client responses."}}
			}
		} else {
			reflected := strings.Contains(strings.ToLower(probe.Headers.Get("Content-Type")), "text/html") && strings.Contains(probe.Body, marker)
			data["unescaped_html_marker_reflected"] = reflected
			if reflected {
				result.Summary = "HTML-shaped input reflected without encoding; browser execution unverified"
				result.Findings = []domain.Finding{{Title: "Unescaped HTML-shaped query input reflected", Description: "A unique harmless marker was reflected in an HTML response without angle-bracket encoding. No script was executed and XSS is not confirmed.", Severity: domain.SevInfo, CWE: "CWE-79", Remediation: "Apply context-aware output encoding and validate untrusted input."}}
			}
		}
		return result, nil
	}}
}

func passwordTool() *Tool {
	return &Tool{Name: "password_spray", Category: "auth", LabOnly: true, Description: "Test one supplied password against at most three disposable lab accounts using JSON POST. No brute-force loops; returns statuses and success markers, never tokens. Loopback lab and exact-action approval required.", Parameters: stringSchema([]string{"url", "usernames", "password"}, "url", "usernames", "password"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ URL, Usernames, Password string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if _, err := labURL(ctx, args.URL); err != nil {
			return nil, err
		}
		users, err := boundedList(args.Usernames, 3)
		if err != nil {
			return nil, err
		}
		if args.Password == "" || len(args.Password) > 1024 {
			return nil, errors.New("one nonempty test password required (maximum 1024 bytes)")
		}
		client := scopedHTTPClient()
		defer client.CloseIdleConnections()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		var checks []map[string]any
		lastStatus := 0
		result := &Result{Success: true, Summary: "Bounded lab authentication checks completed; inspect individual statuses"}
		for index, user := range users {
			if index > 0 {
				timer := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil, ctx.Err()
				case <-timer.C:
				}
			}
			body, _ := json.Marshal(map[string]string{"email": user, "password": args.Password})
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, args.URL, strings.NewReader(string(body)))
			if err != nil {
				return nil, err
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := client.Do(request)
			if err != nil {
				return nil, err
			}
			payload, readError := io.ReadAll(io.LimitReader(response.Body, 65536))
			response.Body.Close()
			if readError != nil {
				return nil, readError
			}
			var document struct{ Authentication struct{ Token string } }
			_ = json.Unmarshal(payload, &document)
			accepted := response.StatusCode >= 200 && response.StatusCode < 300 && document.Authentication.Token != ""
			lastStatus = response.StatusCode
			check := map[string]any{"username": user, "status": response.StatusCode, "token_returned": accepted}
			if accepted {
				fingerprint := sha256.Sum256([]byte(document.Authentication.Token))
				check["token_fingerprint"] = hex.EncodeToString(fingerprint[:8])
				result.Credentials = append(result.Credentials, domain.Credential{Type: "bearer", Username: user, Value: document.Authentication.Token, TargetID: args.URL})
			}
			checks = append(checks, check)
			if response.StatusCode == 429 {
				result.Summary = "Authentication checks stopped at server rate limit"
				break
			}
		}
		result.Data = map[string]any{"status": lastStatus, "checks": checks, "success_criterion": "2xx response with a nonempty authentication.token field; authorization privileges not verified"}
		return result, nil
	}}
}
