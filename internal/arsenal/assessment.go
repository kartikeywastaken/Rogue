package arsenal

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Schemas use string fields so validation remains uniform across hosted and
// local models. Lists are bounded comma-separated values, never shell text.
func stringSchema(required []string, fields ...string) map[string]any {
	if required == nil {
		required = []string{}
	}
	properties := make(map[string]any, len(fields))
	for _, field := range fields {
		properties[field] = map[string]any{"type": "string"}
	}
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}

func RegisterAssessmentTools(registry *Registry) {
	registry.Register(tlsTool())
	registry.Register(webReviewTool())
	registry.Register(discoveryTool())
	registry.Register(subdomainTool())
	registry.Register(base64Tool())
	jwt := jwtTool()
	jwt.SensitiveArgs = []string{"token"}
	registry.Register(jwt)
	hash := hashTool()
	hash.SensitiveArgs = []string{"candidates"}
	registry.Register(hash)
}

func tlsTool() *Tool {
	return &Tool{Name: "ssl_scan", Category: "vuln", Description: "Verify a TLS handshake, certificate chain, hostname, expiry and negotiated protocol. Does not enumerate all supported ciphers/protocols.", Parameters: stringSchema([]string{"host"}, "host", "port"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Host, Port string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if args.Port == "" {
			args.Port = "443"
		}
		if !validPort(args.Port) {
			return nil, errors.New("port must be 1–65535")
		}
		operation, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		connection, err := scopedDial(operation, "tcp", net.JoinHostPort(args.Host, args.Port))
		if err != nil {
			return nil, err
		}
		defer connection.Close()
		secure := tls.Client(connection, &tls.Config{ServerName: args.Host, MinVersion: tls.VersionTLS12})
		if err = secure.HandshakeContext(operation); err != nil {
			return nil, fmt.Errorf("verified TLS handshake: %w", err)
		}
		state := secure.ConnectionState()
		certificate := state.PeerCertificates[0]
		return &Result{Success: true, Summary: "TLS certificate verified; one negotiated configuration observed", Data: map[string]any{"host": args.Host, "port": args.Port, "protocol": tls.VersionName(state.Version), "cipher": tls.CipherSuiteName(state.CipherSuite), "issuer": certificate.Issuer.String(), "dns_names": certificate.DNSNames, "not_after": certificate.NotAfter, "days_remaining": int(time.Until(certificate.NotAfter).Hours() / 24)}}, nil
	}}
}

func validPort(raw string) bool {
	value := 0
	if raw == "" {
		return false
	}
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return false
		}
		value = value*10 + int(digit-'0')
		if value > 65535 {
			return false
		}
	}
	return value > 0
}

type webSample struct {
	URL     string
	Status  int
	Headers http.Header
	Body    string
}

func fetchSample(ctx context.Context, client *http.Client, raw string) (webSample, error) {
	var sample webSample
	if _, err := checkURL(ctx, raw); err != nil {
		return sample, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return sample, err
	}
	response, err := client.Do(request)
	if err != nil {
		return sample, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return sample, err
	}
	return webSample{response.Request.URL.String(), response.StatusCode, response.Header, string(body)}, nil
}

func webReviewTool() *Tool {
	return &Tool{Name: "technology_detect", Category: "web", Description: "Observe server/framework hints and cookie/authentication configuration from one scoped GET. Hints are not confirmed versions or vulnerabilities; no credentials are submitted.", Parameters: stringSchema([]string{"url"}, "url"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ URL string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		client := scopedHTTPClient()
		defer client.CloseIdleConnections()
		sample, err := fetchSample(ctx, client, args.URL)
		if err != nil {
			return nil, err
		}
		hints := map[string]string{}
		for _, header := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "WWW-Authenticate"} {
			if value := sample.Headers.Get(header); value != "" {
				hints[header] = value
			}
		}
		var cookies []map[string]any
		response := http.Response{Header: sample.Headers}
		for _, cookie := range response.Cookies() {
			cookies = append(cookies, map[string]any{"name": cookie.Name, "secure": cookie.Secure, "http_only": cookie.HttpOnly, "same_site": cookie.SameSite})
		}
		return &Result{Success: true, Summary: fmt.Sprintf("HTTP %d; %d technology/auth hints; cookie values omitted", sample.Status, len(hints)), Data: map[string]any{"url": sample.URL, "status": sample.Status, "hints": hints, "cookies": cookies, "limitation": "Headers may be absent or misleading. Cookie flags alone do not establish exploitability."}}, nil
	}}
}

func boundedList(raw string, limit int) ([]string, error) {
	var values []string
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value != "" && !slices.Contains(values, value) {
			values = append(values, value)
		}
	}
	if len(values) == 0 || len(values) > limit {
		return nil, fmt.Errorf("provide 1–%d distinct values", limit)
	}
	return values, nil
}

func discoveryTool() *Tool {
	return &Tool{Name: "dir_bruteforce", Category: "web", Description: "Check up to 16 explicit same-origin paths with GET. Reports status codes, not a claim that a resource exists (soft 404s are possible).", Parameters: stringSchema([]string{"url", "paths"}, "url", "paths"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ URL, Paths string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		base, err := checkURL(ctx, args.URL)
		if err != nil {
			return nil, err
		}
		paths, err := boundedList(args.Paths, 16)
		if err != nil {
			return nil, err
		}
		urls := make([]string, 0, len(paths))
		for _, path := range paths {
			reference, err := url.Parse(path)
			if err != nil || reference.IsAbs() || reference.Host != "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
				return nil, errors.New("paths must start with a single / and remain on the original origin")
			}
			urls = append(urls, base.ResolveReference(reference).String())
		}
		client := scopedHTTPClient()
		defer client.CloseIdleConnections()
		// Record redirects without following them during path enumeration.
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		var results []map[string]any
		completed := 0
		for _, address := range urls {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			sample, err := fetchSample(ctx, client, address)
			if err != nil {
				results = append(results, map[string]any{"url": address, "error": err.Error()})
				continue
			}
			results = append(results, map[string]any{"url": address, "status": sample.Status, "sample_bytes": len(sample.Body)})
			completed++
		}
		if completed == 0 {
			return &Result{Success: false, Summary: "All path checks failed", Error: "no HTTP response obtained", Data: map[string]any{"checks": results}}, nil
		}
		return &Result{Success: true, Summary: "Path checks completed; inspect per-path errors and soft-404 uncertainty", Data: map[string]any{"checks": results}}, nil
	}}
}

func subdomainTool() *Tool {
	return &Tool{Name: "subdomain_enum", Category: "recon", Description: "Resolve up to 32 explicit subdomain labels. Every resulting hostname must be separately in mission scope; no wildcard scope is inferred.", Parameters: stringSchema([]string{"host", "labels"}, "host", "labels"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Host, Labels string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if err := checkHost(ctx, args.Host); err != nil {
			return nil, err
		}
		labels, err := boundedList(args.Labels, 32)
		if err != nil {
			return nil, err
		}
		for _, label := range labels {
			if len(label) > 63 || strings.Trim(label, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return nil, errors.New("invalid DNS label")
			}
			if err := checkHost(ctx, label+"."+args.Host); err != nil {
				return nil, err
			}
		}
		var results []map[string]any
		for _, label := range labels {
			operation, cancel := context.WithTimeout(ctx, 3*time.Second)
			addresses, err := net.DefaultResolver.LookupHost(operation, label+"."+args.Host)
			cancel()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			item := map[string]any{"host": label + "." + args.Host, "addresses": addresses}
			if err != nil {
				item["error"] = err.Error()
			}
			results = append(results, item)
		}
		return &Result{Success: true, Summary: "DNS candidate checks completed; wildcard DNS may produce false positives", Data: map[string]any{"checks": results}}, nil
	}}
}

func base64Tool() *Tool {
	return &Tool{Name: "base64_decode", Category: "util", Description: "Decode standard or URL-safe Base64 locally (maximum input 16 KiB).", Parameters: stringSchema([]string{"value"}, "value"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Value string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if len(args.Value) > 16384 {
			return nil, errors.New("input exceeds 16 KiB")
		}
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if data, err := encoding.DecodeString(args.Value); err == nil {
				return &Result{Success: true, Summary: "Base64 decoded; encoding provides no confidentiality", Data: map[string]any{"text": string(data), "hex": hex.EncodeToString(data)}}, nil
			}
		}
		return nil, errors.New("invalid Base64")
	}}
}

func jwtTool() *Tool {
	return &Tool{Name: "jwt_decode", Category: "util", Description: "Inspect JWT header and claims locally. Does not verify the signature, issuer, audience or authorization.", Parameters: stringSchema([]string{"token"}, "token"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Token string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if len(args.Token) > 16384 {
			return nil, errors.New("token exceeds 16 KiB")
		}
		parts := strings.Split(args.Token, ".")
		if len(parts) != 3 {
			return nil, errors.New("expected a three-part JWT")
		}
		var values [2]map[string]any
		for index := range values {
			data, err := base64.RawURLEncoding.DecodeString(parts[index])
			if err != nil {
				return nil, err
			}
			if err = json.Unmarshal(data, &values[index]); err != nil || values[index] == nil {
				return nil, errors.New("JWT header and claims must be JSON objects")
			}
		}
		return &Result{Success: true, Summary: "JWT decoded; all claims remain unverified", Data: map[string]any{"header": values[0], "claims": values[1], "signature_verified": false}}, nil
	}}
}

func hashTool() *Tool {
	return &Tool{Name: "hash_crack", Category: "auth", Description: "Compare a SHA-256 digest against up to 64 supplied candidates locally; no network login attempts. Matching plaintext is not returned.", Parameters: stringSchema([]string{"hash", "candidates"}, "hash", "candidates"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Hash, Candidates string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		digest, err := hex.DecodeString(args.Hash)
		if err != nil || len(digest) != sha256.Size {
			return nil, errors.New("expected a SHA-256 hex digest")
		}
		candidates, err := boundedList(args.Candidates, 64)
		if err != nil {
			return nil, err
		}
		matched := -1
		for index, candidate := range candidates {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			sum := sha256.Sum256([]byte(candidate))
			if slices.Equal(sum[:], digest) {
				matched = index
				break
			}
		}
		return &Result{Success: true, Summary: "Local SHA-256 candidate comparison completed", Data: map[string]any{"matched_index": matched, "candidate_count": len(candidates), "limitation": "Only the supplied candidates were checked; no match is not evidence of password strength."}}, nil
	}}
}
