package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"rogue/internal/arsenal"
	"rogue/internal/engine"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/testutil"
)

func TestFlagScoreAndMatrixMappingAndLocalCTFSuite(t *testing.T) {
	if s := FlagScore("The answer is flag{abc_123} verified.", "flag{abc_123}"); s != 1.0 {
		t.Fatalf("expected exact flag score 1.0 when embedded in prose, got %.2f", s)
	}
	if s := FlagScore("FLAG{ABC_123}", "flag{abc_123}"); s != 0.75 {
		t.Fatalf("expected case-insensitive score 0.75, got %.2f", s)
	}

	mat := CompareMatrices(
		Result{CWEsFound: []string{"CWE-89", "CWE-284"}},
		[]string{"A01:2021", "A03:2021", "A10:2021"},
		[]string{"T1190", "T1059"},
		[]string{"CWE-89"},
	)
	if !slices.Contains(mat.OWASPCoverage, "A03:2021") || !slices.Contains(mat.MITRECoverage, "T1190") {
		t.Fatalf("expected mapped OWASP & MITRE coverage, got %+v", mat)
	}

	suite := LocalCTFSuite(filepath.Join("..", "..", "ctf", "challenges"))
	if len(suite.Cases) != 5 {
		t.Fatalf("expected 5 local CTF fixture cases, got %d (%s)", len(suite.Cases), suite.Description)
	}
	if cat := AllCategoriesSuite("."); len(cat.Cases) != 5 {
		t.Fatalf("expected 5 multi-domain category cases, got %d", len(cat.Cases))
	}
	if x := XBOWSuite(""); len(x.Cases) != 10 {
		t.Fatalf("expected 10 XBOW cases, got %d", len(x.Cases))
	}
}

func TestRunnerScoresCTFFlagsAndCategoryBreakdownWithJudge(t *testing.T) {
	transport := testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		bodyBytes, _ := io.ReadAll(r.Body)
		content := "Solved! Captured flag{header_recon_verified}."
		if strings.Contains(string(bodyBytes), "security benchmark grader") {
			content = `{"score": 0.9, "reason": "partial match verified"}`
		} else if strings.Contains(string(bodyBytes), "crypto-partial") {
			content = "Partial progress on XOR key."
		}
		chunk := map[string]any{
			"choices": []any{map[string]any{"delta": map[string]any{"content": content}, "finish_reason": "stop"}},
		}
		data, _ := json.Marshal(chunk)
		payload := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", data)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
	})
	client := &llm.Client{Endpoint: "https://fixture.invalid/chat", Client: &http.Client{Transport: transport}}
	h := engine.NewHarnessWithOptions(client, arsenal.New(), []string{"fixture"}, "fixture", engine.Options{
		SingleOperator: true,
		Rules:          mission.Rules{Scope: []string{"127.0.0.1"}},
	})
	runner := NewRunner(h).WithJudge(client, "fixture")

	suite := Suite{
		Name: "ctf-eval",
		Cases: []Case{
			{
				Name: "web-flag", Category: "web",
				Prompt: "Find header flag", Mode: "plan",
				Expected: Expected{ExpectedFlag: "flag{header_recon_verified}"},
			},
			{
				Name: "crypto-partial", Category: "crypto",
				Prompt: "crypto-partial XOR check", Mode: "plan",
				Expected: Expected{ExpectedFlag: "flag{unseen_flag}"},
			},
		},
	}

	sr := runner.Run(context.Background(), suite)
	if len(sr.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(sr.Results))
	}
	if !sr.Results[0].FlagMatched || !sr.Results[0].Passed {
		t.Fatalf("expected exact flag match and pass on case 0, got %+v", sr.Results[0])
	}
	if sr.Results[1].JudgeScore != 0.9 {
		t.Fatalf("expected LLM judge score 0.9 on partial case, got %+v", sr.Results[1])
	}
	if _, ok := sr.ByCategory["web"]; !ok {
		t.Fatalf("expected ByCategory breakdown for web, got %+v", sr.ByCategory)
	}
}
