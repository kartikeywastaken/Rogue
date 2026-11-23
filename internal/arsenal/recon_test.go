package arsenal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"rogue/internal/testutil"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"rogue/internal/mission"
)

func scoped(mode string, scope ...string) context.Context {
	return WithPolicy(context.Background(), Policy{Mode: mode, Rules: mission.Rules{Scope: scope}, Categories: []string{"recon"}})
}
func registry() *Registry        { r := New(); RegisterReconTools(r); return r }
func args(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func TestDNSAUsesIP4Network(t *testing.T) {
	r := registry()
	res, err := r.Exec(scoped("auto", "localhost"), "dns_lookup", args(map[string]string{"host": "localhost", "record_type": "A"}))
	if err != nil || !res.Success {
		t.Fatal(res, err)
	}
	for _, record := range res.Data.(map[string]any)["records"].([]string) {
		if net.ParseIP(record).To4() == nil {
			t.Fatal("AAAA returned for A", record)
		}
	}
}
func TestPolicyAndSchemaDenyBeforeSideEffects(t *testing.T) {
	var hits atomic.Int32
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, tc := range []struct{ name, mode, scope, raw string }{
		{"plan", "plan", "127.0.0.1", string(args(map[string]string{"url": srv.URL}))},
		{"approval", "default", "127.0.0.1", string(args(map[string]string{"url": srv.URL}))},
		{"scope", "auto", "example.invalid", string(args(map[string]string{"url": srv.URL}))},
		{"method", "auto", "127.0.0.1", string(args(map[string]string{"url": srv.URL, "method": "DELETE"}))},
		{"unknown field", "auto", "127.0.0.1", string(args(map[string]string{"url": srv.URL, "extra": "bad"}))},
		{"null", "auto", "127.0.0.1", `{"url":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry().Exec(scoped(tc.mode, tc.scope), "http_request", json.RawMessage(tc.raw))
			if err == nil {
				t.Fatal("accepted forbidden call")
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatal("denied calls reached network")
	}
	ctx := WithPolicy(context.Background(), Policy{Mode: "default", Categories: []string{"recon"}, Rules: mission.Rules{Scope: []string{"127.0.0.1"}, PreapprovedTools: []string{"http_request"}}})
	if res, err := registry().Exec(ctx, "http_request", args(map[string]string{"url": srv.URL})); err != nil || !res.Success {
		t.Fatal(res, err)
	}
}
func TestRedirectCannotEscapeScope(t *testing.T) {
	var escaped atomic.Int32
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/escaped" {
			escaped.Add(1)
			return
		}
		u := *r.URL
		u.Scheme = "http"
		u.Host = strings.Replace(r.Host, "127.0.0.1", "localhost", 1)
		u.Path = "/escaped"
		http.Redirect(w, r, u.String(), http.StatusFound)
	}))
	defer srv.Close()
	res, err := registry().Exec(scoped("auto", "127.0.0.1"), "http_request", args(map[string]string{"url": srv.URL}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Success || escaped.Load() != 0 {
		t.Fatal("redirect escaped scope")
	}
}
func TestHTTPAndHeaderObservations(t *testing.T) {
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		fmt.Fprint(w, strings.Repeat("x", 5000))
	}))
	defer srv.Close()
	r := registry()
	res, err := r.Exec(scoped("auto", "127.0.0.1"), "http_request", args(map[string]string{"url": srv.URL}))
	if err != nil || !res.Success {
		t.Fatal(res, err)
	}
	data := res.Data.(map[string]any)
	if !data["truncated"].(bool) || len(data["body"].(string)) != 4096 {
		t.Fatal("body bounds missing")
	}
	res, err = r.Exec(scoped("auto", "127.0.0.1"), "header_analysis", args(map[string]string{"url": srv.URL}))
	if err != nil || !res.Success || len(res.Findings) == 0 {
		t.Fatal(res, err)
	}
	for _, f := range res.Findings {
		if f.Title == "Missing Content-Security-Policy" {
			t.Fatal("present header reported missing")
		}
	}
}
func TestPortScanOpenInvalidAndCancelled(t *testing.T) {
	srv := testutil.NewServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	res, err := registry().Exec(scoped("auto", "127.0.0.1"), "port_scan", args(map[string]string{"host": "127.0.0.1", "ports": fmt.Sprint(port)}))
	if err != nil || !res.Success {
		t.Fatal(res, err)
	}
	open := res.Data.(map[string]any)["open_ports"].([]int)
	if len(open) != 1 || open[0] != port {
		t.Fatal(open)
	}
	if _, err := registry().Exec(scoped("auto", "127.0.0.1"), "port_scan", args(map[string]string{"host": "127.0.0.1", "ports": "80,not-a-port"})); err == nil {
		t.Fatal("ignored bad port")
	}
	ctx, cancel := context.WithCancel(scoped("auto", "127.0.0.1"))
	cancel()
	if _, err := registry().Exec(ctx, "port_scan", args(map[string]string{"host": "127.0.0.1"})); err == nil {
		t.Fatal("cancelled call executed")
	}
}
