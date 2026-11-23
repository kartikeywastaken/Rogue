package arsenal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"rogue/internal/target"
	"rogue/internal/testutil"
)

type runnerFunc func(context.Context, string, []string) ([]byte, error)

func (runner runnerFunc) Run(ctx context.Context, path string, arguments []string) ([]byte, error) {
	return runner(ctx, path, arguments)
}

func TestNmapUsesPinnedArgumentsAndStructuredOutput(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, _ string, arguments []string) ([]byte, error) {
		if arguments[len(arguments)-1] != "127.0.0.1" || !slices.Contains(arguments, "-n") || !slices.Contains(arguments, "-sT") {
			t.Fatal("target was not pinned", arguments)
		}
		for _, argument := range arguments {
			if strings.Contains(argument, "--script") || argument == "-A" {
				t.Fatal("unexpected active script option")
			}
		}
		return []byte(`<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="fixture" version="1.0"><cpe>cpe:/a:fixture:server:1.0</cpe></service></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`), nil
	})
	registry := New()
	RegisterExternalTools(registry, ExternalOptions{Runner: runner, NmapPath: "/usr/bin/true"})
	result, err := registry.Exec(scoped("auto", "127.0.0.1"), "nmap_scan", args(map[string]string{"host": "127.0.0.1", "ports": "80,443"}))
	if err != nil || !result.Success {
		t.Fatal(result, err)
	}
	services := result.Data.(map[string]any)["services"].([]target.Service)
	if len(services) != 1 || services[0].Product != "fixture" {
		t.Fatal(services)
	}
	if _, err := selectedPorts("80;touch /tmp/not-a-command"); err == nil {
		t.Fatal("accepted nonnumeric port input")
	}
}

func TestCVELookupUsesNVDAndCachesReferenceData(t *testing.T) {
	requests := 0
	transport := testutil.RoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Query().Get("cveId") != "CVE-2021-44228" {
			t.Fatal(request.URL)
		}
		body := `{"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"reference description"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":10,"baseSeverity":"CRITICAL"}}]},"references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}]}}]}`
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	client := &CVEClient{Client: &http.Client{Transport: transport}}
	registry := New()
	RegisterCVETool(registry, client)
	for range 2 {
		result, err := registry.Exec(scoped("auto"), "cve_lookup", json.RawMessage(`{"cve_id":"CVE-2021-44228"}`))
		if err != nil || !result.Success || len(result.Findings) != 0 {
			t.Fatal("lookup should return references, not assert a target finding", result, err)
		}
		records := result.Data.(map[string]any)["records"].([]CVE)
		if len(records) != 1 || records[0].Score != 10 {
			t.Fatal(records)
		}
	}
	if requests != 1 {
		t.Fatal("lookup cache did not reuse the record")
	}
}
