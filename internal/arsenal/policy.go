package arsenal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"rogue/internal/mission"
)

type Policy struct {
	Mode       string
	Rules      mission.Rules
	Categories []string // nil means unrestricted; empty means no tools
	Approve    func(string, json.RawMessage) error
	Lab        bool
}
type policyKey struct{}

func WithPolicy(ctx context.Context, p Policy) context.Context {
	return context.WithValue(ctx, policyKey{}, p)
}

func authorize(ctx context.Context, t *Tool, args json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, ok := ctx.Value(policyKey{}).(Policy)
	if !ok {
		return errors.New("execution policy required")
	}
	if p.Mode == "plan" {
		return errors.New("plan mode: tool execution disabled")
	}
	if p.Mode != "default" && p.Mode != "auto" {
		return errors.New("invalid execution mode")
	}
	if p.Categories != nil && !slices.Contains(p.Categories, t.Category) {
		return errors.New("tool not permitted for this operator")
	}
	if t.LabOnly && !p.Lab {
		return errors.New("tool requires explicit ROGUE_LAB=true")
	}
	if !t.Internal && len(p.Rules.AllowedTools) > 0 && !slices.Contains(p.Rules.AllowedTools, t.Name) {
		return errors.New("tool excluded by mission rules")
	}
	if t.LabOnly {
		if p.Approve == nil {
			return errors.New("exact-action approval required for lab operation")
		}
		return p.Approve(t.Name, args)
	}
	if !t.Internal && p.Mode == "default" && !slices.Contains(p.Rules.PreapprovedTools, t.Name) {
		if p.Approve != nil {
			return p.Approve(t.Name, args)
		}
		return errors.New("approval required: configure explicit preapproval or select auto mode within mission scope")
	}
	return nil
}

func labURL(ctx context.Context, raw string) (*url.URL, error) {
	u, err := checkURL(ctx, raw)
	if err != nil {
		return nil, err
	}
	policy, _ := ctx.Value(policyKey{}).(Policy)
	ip := net.ParseIP(u.Hostname())
	if !policy.Lab || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("lab operations require a literal loopback IP and explicit lab mode")
	}
	return u, nil
}

func checkHost(ctx context.Context, host string) error {
	p, ok := ctx.Value(policyKey{}).(Policy)
	if !ok || !p.Rules.AllowsHost(host) {
		return fmt.Errorf("target %q is outside mission scope", host)
	}
	return nil
}

func checkURL(ctx context.Context, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, errors.New("URL must be HTTP(S), with a host and no embedded credentials")
	}
	if err := checkHost(ctx, u.Hostname()); err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	if err := checkPort(ctx, port); err != nil {
		return nil, err
	}
	return u, nil
}

func checkPort(ctx context.Context, raw string) error {
	policy, ok := ctx.Value(policyKey{}).(Policy)
	port, err := strconv.Atoi(raw)
	if !ok || err != nil || !policy.Rules.AllowsPort(port) {
		return fmt.Errorf("port %q is outside mission scope", raw)
	}
	return nil
}

// Resolve once, validate the peer, then dial a literal IP. Redirects are checked
// separately, so neither DNS rebinding nor a redirect bypasses mission scope.
func scopedDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if err := checkHost(ctx, host); err != nil {
		return nil, err
	}
	if err := checkPort(ctx, port); err != nil {
		return nil, err
	}
	p := ctx.Value(policyKey{}).(Policy)
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error = errors.New("no authorized address for target")
	for _, ip := range ips {
		if !p.Rules.AllowsAddress(host, ip.IP.String()) {
			last = errors.New("resolved address excluded by mission rules")
			continue
		}
		conn, dialErr := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		last = dialErr
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}

func scopedHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DialContext: scopedDial, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("redirect limit reached")
			}
			_, err := checkURL(req.Context(), req.URL.String())
			return err
		},
	}
}
