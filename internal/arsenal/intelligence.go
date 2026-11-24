package arsenal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"rogue/internal/analysis"
	"strings"
)

type secretPattern struct {
	name       string
	expression *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
	{"github_classic", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{"github_fine_grained", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{50,255}\b`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}\b`)},
	{"google_oauth", regexp.MustCompile(`\bya29\.[A-Za-z0-9_-]{20,255}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,255}\b`)},
	{"stripe_secret", regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{20,255}\b`)},
	{"groq_key", regexp.MustCompile(`\bgsk_[A-Za-z0-9]{40,255}\b`)},
	{"openai_key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)},
	{"database_uri", regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@[^\s]+`)},
	{"rsa_private_key", regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`)},
	{"ec_private_key", regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`)},
	{"openssh_private_key", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`)},
	{"pkcs8_private_key", regexp.MustCompile(`-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----`)},
	{"assigned_secret", regexp.MustCompile(`(?i)(?:aws_secret_access_key|api_secret|client_secret|secret_key)["' ]*[:=]["' ]*[A-Za-z0-9/+_=.-]{16,255}`)},
}

type SecretMatch struct {
	Kind, Fingerprint string
	Offset            int
}

func ScanSecrets(value string) []SecretMatch {
	var matches []SecretMatch
	for _, pattern := range secretPatterns {
		for _, position := range pattern.expression.FindAllStringIndex(value, 16) {
			digest := sha256.Sum256([]byte(value[position[0]:position[1]]))
			matches = append(matches, SecretMatch{Kind: pattern.name, Fingerprint: hex.EncodeToString(digest[:8]), Offset: position[0]})
			if len(matches) == 64 {
				return matches
			}
		}
	}
	return matches
}

func RegisterIntelligenceTools(registry *Registry) {
	registry.Register(&Tool{Name: "cvss_score", Category: "util", Description: "Calculate a CVSS v3.1 base score from all eight explicitly supplied metrics. This scores the supplied vector, not target exploitability.", Parameters: stringSchema([]string{"vector"}, "vector"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Vector string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		score, err := analysis.BaseScore(args.Vector)
		if err != nil {
			return nil, err
		}
		return &Result{Success: true, Summary: fmt.Sprintf("CVSS v3.1 base score %.1f from supplied vector", score), Data: map[string]any{"vector": args.Vector, "score": score, "metrics_verified": false}}, nil
	}})
	registry.Register(&Tool{Name: "secret_scan", Category: "util", SensitiveArgs: []string{"text"}, Description: "Inspect supplied text against 16 secret patterns locally. Returns kinds, offsets and fingerprints only; a pattern match does not establish that a credential is live.", Parameters: stringSchema([]string{"text"}, "text"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Text string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if len(args.Text) > 65536 {
			return nil, errors.New("text exceeds 64 KiB")
		}
		matches := ScanSecrets(args.Text)
		return &Result{Success: true, Summary: fmt.Sprintf("%d potential secret patterns; values withheld", len(matches)), Data: map[string]any{"matches": matches, "verified_credentials": false}}, nil
	}})
	for _, name := range []string{"session_check", "exposure_check", "cleanup_verify"} {
		registry.Register(labReadTool(name))
	}
}

func labReadTool(name string) *Tool {
	category, description := "lab", "Collect up to 64 KiB from one lab URL; report byte count, body fingerprint and potential secret patterns. No onward data transfer."
	if name == "session_check" {
		category = "auth"
		description = "GET a lab endpoint using a captured credential ID or explicit test token. Report status and fingerprint without returning protected content or token. A 2xx response does not prove elevated privileges."
	}
	if name == "cleanup_verify" {
		description = "Check whether a supplied marker remains in one lab response. This verifies that endpoint only and does not deploy persistence or claim to have performed cleanup."
	}
	return &Tool{Name: name, Category: category, LabOnly: true, SensitiveArgs: []string{"token"}, Description: description + " Exact-action approval and a literal loopback target are required.", Parameters: stringSchema([]string{"url"}, "url", "credential_id", "token", "marker"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct {
			URL           string
			CredentialID  string `json:"credential_id"`
			Token, Marker string
		}
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if _, err := labURL(ctx, args.URL); err != nil {
			return nil, err
		}
		if args.CredentialID != "" && args.Token != "" {
			return nil, errors.New("supply credential_id or token, not both")
		}
		if name == "cleanup_verify" && (args.Marker == "" || len(args.Marker) > 256) {
			return nil, errors.New("cleanup marker required (maximum 256 bytes)")
		}
		token := args.Token
		if args.CredentialID != "" {
			services, _ := ctx.Value(servicesKey{}).(Services)
			if services.Credential == nil {
				return nil, errors.New("mission credential service unavailable")
			}
			value, err := services.Credential(args.CredentialID, args.URL)
			if err != nil {
				return nil, err
			}
			token = value
		}
		if name == "session_check" && token == "" {
			return nil, errors.New("session check requires an explicitly supplied lab credential")
		}
		if len(token) > 16384 || strings.ContainsAny(token, "\r\n") {
			return nil, errors.New("invalid bearer token")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, args.URL, nil)
		if err != nil {
			return nil, err
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		client := scopedHTTPClient()
		defer client.CloseIdleConnections()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil {
			return nil, err
		}
		truncated := len(body) > 65536
		if truncated {
			body = body[:65536]
		}
		digest := sha256.Sum256(body)
		data := map[string]any{"url": args.URL, "status": response.StatusCode, "sample_bytes": len(body), "sha256": hex.EncodeToString(digest[:]), "truncated": truncated}
		if args.CredentialID != "" {
			data["credential_id"] = args.CredentialID
		}
		if name == "session_check" {
			baseline, err := fetchSample(ctx, client, args.URL)
			if err != nil {
				return nil, err
			}
			data["baseline_status"] = baseline.Status
			data["authenticated_access_confirmed"] = (baseline.Status == 401 || baseline.Status == 403) && response.StatusCode >= 200 && response.StatusCode < 300
		}
		summary := "Lab endpoint read completed; no privileged access or onward transfer inferred"
		if name == "exposure_check" {
			data["potential_secrets"] = ScanSecrets(string(body))
		}
		if name == "cleanup_verify" {
			data["marker_present"] = strings.Contains(string(body), args.Marker)
			data["absence_verified_in_complete_response"] = !truncated && !strings.Contains(string(body), args.Marker)
			summary = "Cleanup marker checked against one endpoint; no cleanup action executed"
		}
		result := &Result{Success: true, Summary: summary, Data: data}
		if name == "exposure_check" {
			result.Artifact = body
			result.ArtifactType = response.Header.Get("Content-Type")
		}
		return result, nil
	}}
}
