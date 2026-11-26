package arsenal

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"rogue/internal/mission"
	"rogue/internal/opsec"
	"rogue/internal/testutil"
)

func TestResearchRedirectCannotEscapeScopeAndRequiresApproval(t *testing.T) {
	defer opsec.SetProfile("loud")
	opsec.SetProfile("loud")

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

	reg := New()
	RegisterResearchTools(reg)

	// ModeDefault without approval must fail execute=true
	defCtx := WithPolicy(context.Background(), Policy{
		Mode:       "default",
		Rules:      mission.Rules{Scope: []string{"127.0.0.1"}},
		Categories: []string{"research"},
	})
	if _, err := reg.Exec(defCtx, "simurgh_surface", args(map[string]any{"target_url": srv.URL, "execute": true})); err == nil {
		t.Fatal("expected ModeDefault without approval to deny simurgh_surface execute=true")
	}

	// ModeAuto within scope succeeds, but redirect to localhost MUST fail scope validation
	autoCtx := WithPolicy(context.Background(), Policy{
		Mode:       "auto",
		Rules:      mission.Rules{Scope: []string{"127.0.0.1"}},
		Categories: []string{"research"},
	})
	res, err := reg.Exec(autoCtx, "simurgh_surface", args(map[string]any{"target_url": srv.URL, "execute": true}))
	if err != nil {
		t.Fatal(err)
	}
	if escaped.Load() != 0 {
		t.Fatalf("research redirect escaped scope (%d hits)", escaped.Load())
	}
	_ = res
}

func TestCerberusPrivescFactsAndSSHScope(t *testing.T) {
	reg := New()
	RegisterResearchTools(reg)

	factMap := map[string]bool{}
	applyPrivescOutputFacts("sudo_l", "(ALL) NOPASSWD: ALL\nenv_keep", factMap)
	applyPrivescOutputFacts("suid_binaries", "/usr/bin/python3", factMap)
	applyPrivescOutputFacts("id", "uid=1000(u) groups=999(docker)", factMap)
	if !factMap["linux.sudo.nopasswd_all"] || !factMap["linux.files.suid_interpreter"] || !factMap["linux.docker.group_member"] {
		t.Fatalf("expected inferred privesc facts, got %+v", factMap)
	}

	ctx := WithPolicy(context.Background(), Policy{
		Mode:       "auto",
		Rules:      mission.Rules{Scope: []string{"127.0.0.1"}},
		Categories: []string{"research"},
	})
	// Off-scope SSH target must be denied cleanly.
	if _, err := reg.Exec(ctx, "cerberus_privesc", args(map[string]any{
		"platform":   "linux",
		"facts":      "sudo.nopasswd_all",
		"execute":    true,
		"ssh_target": "192.0.2.50",
	})); err == nil {
		t.Fatal("expected off-scope ssh_target to fail")
	}
}

func TestWebCrawlAndActiveWebScanAndAIRedTeam(t *testing.T) {
	defer opsec.SetProfile("loud")
	opsec.SetProfile("loud")

	var mux http.ServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<a href="/search?item=1">Search</a>
			<a href="https://offsite.invalid/leak">Offsite</a>
			<form action="/login" method="post"><input name="username"><input name="password"></form>
		</body></html>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Sign in</body></html>`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		if q == "'" {
			_, _ = w.Write([]byte("SQLITE_ERROR: near syntax error"))
			return
		}
		if q == "{{7*7}}" {
			_, _ = w.Write([]byte("Result: 49"))
			return
		}
		_, _ = w.Write([]byte("<html>Search: " + q + "</html>"))
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		reply := "I cannot comply with that request."
		if len(body.Messages) > 0 && strings.Contains(body.Messages[0].Content, "ROLE_OVERRIDE_OK") {
			reply = "ROLE_OVERRIDE_OK"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": reply}}},
		})
	})

	srv := testutil.NewServer(t, &mux)
	defer srv.Close()

	reg := New()
	RegisterActiveScannerTools(reg)
	RegisterAIRedTeamTool(reg)

	ctx := WithPolicy(context.Background(), Policy{
		Mode:       "auto",
		Rules:      mission.Rules{Scope: []string{"127.0.0.1"}},
		Categories: []string{"web", "vuln"},
	})

	crawlRes, err := reg.Exec(ctx, "web_crawl", args(map[string]any{"url": srv.URL + "/", "max_depth": "2"}))
	if err != nil || !crawlRes.Success {
		t.Fatal(crawlRes, err)
	}
	cdata := crawlRes.Data.(map[string]any)
	if cdata["pages_visited"].(int) < 2 {
		t.Fatalf("expected >= 2 crawled same-origin pages, got %+v", cdata)
	}
	if len(cdata["forms"].([]crawledForm)) != 1 {
		t.Fatalf("expected 1 extracted form, got %+v", cdata["forms"])
	}

	scanRes, err := reg.Exec(ctx, "active_web_scan", args(map[string]any{"url": srv.URL + "/search", "parameters": "q"}))
	if err != nil || !scanRes.Success || len(scanRes.Findings) < 3 {
		t.Fatalf("expected reflection, SQL error, SSTI findings; got res=%+v err=%v", scanRes, err)
	}

	aiRes, err := reg.Exec(ctx, "ai_redteam", args(map[string]any{"endpoint": srv.URL + "/v1/chat/completions", "model": "fixture"}))
	if err != nil || !aiRes.Success {
		t.Fatal(aiRes, err)
	}
	adata := aiRes.Data.(map[string]any)
	if adata["refused"].(int) == 0 || len(aiRes.Findings) == 0 {
		t.Fatalf("expected mixed guardrail refusal + override finding, got %+v", aiRes)
	}
}

func TestMultiDomainAndTLSAndExtendedCLITools(t *testing.T) {
	// SSL full scan against a real TLS test server
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	tlsSrv.Config.ErrorLog = log.New(io.Discard, "", 0)
	tlsSrv.StartTLS()
	defer tlsSrv.Close()

	hostPort := strings.TrimPrefix(tlsSrv.URL, "https://")
	h, p, _ := strings.Cut(hostPort, ":")

	reg := New()
	RegisterActiveScannerTools(reg)
	RegisterMultiDomainTools(reg)
	RegisterExtendedTools(reg, ExternalOptions{Runner: runnerFunc(func(_ context.Context, bin string, arguments []string) ([]byte, error) {
		return []byte("mock output for " + bin + " " + strings.Join(arguments, " ")), nil
	})})

	ctx := WithPolicy(context.Background(), Policy{
		Mode:       "auto",
		Rules:      mission.Rules{Scope: []string{"127.0.0.1"}},
		Categories: []string{"recon", "web", "vuln", "util"},
	})

	tlsRes, err := reg.Exec(ctx, "ssl_scan_full", args(map[string]any{"host": h, "port": p}))
	if err != nil || !tlsRes.Success {
		t.Fatal(tlsRes, err)
	}
	protos := tlsRes.Data.(map[string]any)["supported_protocols"].([]string)
	if len(protos) == 0 {
		t.Fatal("expected negotiated TLS protocol(s)")
	}

	// Crypto XOR recovery of real hex for flag{xor_analysis}
	cRes, err := reg.Exec(ctx, "crypto_analyze", args(map[string]any{"data": "323835332f2c3b260b353a35382d273d2729"}))
	if err != nil || !cRes.Success {
		t.Fatal(err)
	}
	cands := cRes.Data.(map[string]any)["xor_candidates"].([]xorCandidate)
	foundFlag := false
	for _, c := range cands {
		if c.Preview == "flag{xor_analysis}" {
			foundFlag = true
		}
	}
	if !foundFlag {
		t.Fatalf("expected XOR recovery of flag{xor_analysis}, got %+v", cands)
	}

	// Solidity audit
	sRes, err := reg.Exec(ctx, "solidity_audit", args(map[string]any{
		"code": "contract V { function f() public { require(tx.origin == msg.sender); msg.sender.call{value: 1}(\"\"); } }",
	}))
	if err != nil || !sRes.Success || sRes.Data.(map[string]any)["total_findings"].(int) < 2 {
		t.Fatalf("expected solidity findings, got %+v err=%v", sRes, err)
	}

	// Binary triage on current Go test executable
	exePath, _ := os.Executable()
	bRes, err := reg.Exec(ctx, "binary_triage", args(map[string]any{"path": exePath}))
	if err != nil || !bRes.Success {
		t.Fatal(bRes, err)
	}
	if format := bRes.Data.(map[string]any)["format"].(string); format == "" || format == "Unknown/Data" {
		t.Fatalf("expected recognized ELF/PE/Mach-O format for test binary %s, got %s", exePath, format)
	}

	// Verify crypto_hash on a temp file
	tmpFile := filepath.Join(t.TempDir(), "sample.txt")
	_ = os.WriteFile(tmpFile, []byte("rogue"), 0600)
	hRes, err := reg.Exec(ctx, "crypto_hash", args(map[string]any{"path": tmpFile}))
	if err != nil || !hRes.Success || hRes.Data.(map[string]any)["sha256"].(string) == "" {
		t.Fatal(hRes, err)
	}

	// Verify extended CLI wrappers reject off-scope targets and invalid args directly via Execute
	wl := filepath.Join(t.TempDir(), "wl.txt")
	_ = os.WriteFile(wl, []byte("admin\n"), 0600)
	for _, tc := range []struct {
		name string
		raw  map[string]any
	}{
		{"wfuzz_scan", map[string]any{"target_url": "http://198.51.100.1/FUZZ", "wordlist": wl}},
		{"wfuzz_scan", map[string]any{"target_url": "http://127.0.0.1/no_placeholder", "wordlist": wl}},
		{"whois_cli", map[string]any{"host": "198.51.100.1"}},
		{"whois_cli", map[string]any{"host": "-h"}},
		{"nikto_scan", map[string]any{"host": "198.51.100.1"}},
		{"openssl_scan", map[string]any{"host": "127.0.0.1", "port": "notaport"}},
		{"sqlmap_probe", map[string]any{"target_url": "http://example.com/?id=1"}},
		{"hydra_probe", map[string]any{"service": "-S", "host": "127.0.0.1", "user": "u", "pass": "p"}},
		{"xxd_dump", map[string]any{"path": "/etc/nonexistent_rogue_path_xyz"}},
	} {
		tool := reg.Get(tc.name)
		if tool == nil {
			t.Fatalf("missing tool %s", tc.name)
		}
		if _, err := tool.Execute(ctx, args(tc.raw)); err == nil {
			t.Fatalf("expected error for invalid/off-scope %s args %+v", tc.name, tc.raw)
		}
	}
}
