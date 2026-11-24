// Package bench provides benchmark suites for evaluating the ROGUE harness
// against controlled CTF targets. Results are scored and compared for regression.
package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"rogue/internal/engine"
)

// ── types ────────────────────────────────────────────────────────────────────

// Suite is a named benchmark collection targeting a specific application.
type Suite struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	TargetURL   string `json:"target_url,omitempty"`
	Cases       []Case `json:"cases"`
}

// Case is a single benchmark scenario within a suite.
type Case struct {
	Name        string   `json:"name"`
	Prompt      string   `json:"prompt"`
	Mode        string   `json:"mode"`
	Expected    Expected `json:"expected"`
	TimeoutSec  int      `json:"timeout_sec,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// Expected defines what a successful benchmark run should produce.
type Expected struct {
	MinFindings    int      `json:"min_findings"`
	MinObservations int     `json:"min_observations"`
	RequiredCWEs   []string `json:"required_cwes,omitempty"`
	RequiredTools  []string `json:"required_tools,omitempty"`
	MaxDurationSec int      `json:"max_duration_sec,omitempty"`
}

// Result captures the outcome of running a single benchmark case.
type Result struct {
	Suite        string        `json:"suite"`
	Case         string        `json:"case"`
	Passed       bool          `json:"passed"`
	Score        float64       `json:"score"`
	Findings     int           `json:"findings"`
	Observations int           `json:"observations"`
	CWEsFound    []string      `json:"cwes_found"`
	ToolsUsed    []string      `json:"tools_used"`
	Duration     time.Duration `json:"duration"`
	Error        string        `json:"error,omitempty"`
	MissionID    string        `json:"mission_id,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
}

// SuiteResult aggregates all results for one suite.
type SuiteResult struct {
	Suite      string    `json:"suite"`
	Results    []Result  `json:"results"`
	TotalScore float64   `json:"total_score"`
	Passed     int       `json:"passed"`
	Failed     int       `json:"failed"`
	Duration   time.Duration `json:"duration"`
	Timestamp  time.Time `json:"timestamp"`
}

// Regression identifies a benchmark that regressed between two runs.
type Regression struct {
	Case      string  `json:"case"`
	Metric    string  `json:"metric"`
	Previous  float64 `json:"previous"`
	Current   float64 `json:"current"`
	Delta     float64 `json:"delta"`
}

// ── runner ───────────────────────────────────────────────────────────────────

// Runner executes benchmark suites against a harness.
type Runner struct {
	harness *engine.Harness
}

func NewRunner(harness *engine.Harness) *Runner {
	return &Runner{harness: harness}
}

// Run executes all cases in a suite and returns aggregate results.
func (r *Runner) Run(ctx context.Context, suite Suite) SuiteResult {
	start := time.Now()
	sr := SuiteResult{Suite: suite.Name, Timestamp: time.Now().UTC()}
	for _, c := range suite.Cases {
		if ctx.Err() != nil {
			sr.Results = append(sr.Results, Result{
				Suite: suite.Name, Case: c.Name,
				Error: ctx.Err().Error(), Timestamp: time.Now().UTC(),
			})
			sr.Failed++
			continue
		}
		result := r.RunCase(ctx, suite.Name, c)
		sr.Results = append(sr.Results, result)
		sr.TotalScore += result.Score
		if result.Passed {
			sr.Passed++
		} else {
			sr.Failed++
		}
	}
	sr.Duration = time.Since(start)
	if len(suite.Cases) > 0 {
		sr.TotalScore /= float64(len(suite.Cases))
	}
	return sr
}

// RunCase executes a single benchmark case.
func (r *Runner) RunCase(ctx context.Context, suiteName string, c Case) Result {
	start := time.Now()
	timeout := time.Duration(c.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	caseCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	mode := engine.ModeAuto
	switch c.Mode {
	case "default":
		mode = engine.ModeDefault
	case "plan":
		mode = engine.ModePlan
	}

	request := engine.Request{Prompt: c.Prompt, Mode: mode}
	var runErr error
	for event := range r.harness.Run(caseCtx, request) {
		if event.Err != nil {
			runErr = event.Err
		}
	}

	// Collect the report from the last run, same pattern as assessment.go.
	var report engine.Report
	if state := r.harness.LastRun(); state != nil {
		if rep, err := r.harness.Report(state.Control.Snapshot().ID); err == nil {
			report = rep
		}
	}

	result := Result{
		Suite:     suiteName,
		Case:      c.Name,
		Duration:  time.Since(start),
		Timestamp: time.Now().UTC(),
		MissionID: report.Mission.ID,
	}

	if runErr != nil {
		result.Error = runErr.Error()
	}

	analysis := engine.Analyze(report)
	result.Findings = analysis.FindingsWithEvidence
	result.Observations = analysis.SuccessfulObservations

	// Collect CWEs
	cweSet := make(map[string]bool)
	for _, f := range report.Evidence.Findings {
		if f.CWE != "" {
			cweSet[f.CWE] = true
		}
	}
	for cwe := range cweSet {
		result.CWEsFound = append(result.CWEsFound, cwe)
	}
	sort.Strings(result.CWEsFound)

	// Collect tools
	for tool := range analysis.ToolCounts {
		result.ToolsUsed = append(result.ToolsUsed, tool)
	}
	sort.Strings(result.ToolsUsed)

	// Score and check pass/fail
	result.Score = Score(result, c.Expected)
	result.Passed = result.Score >= 0.5 && result.Error == ""
	return result
}

// ── scoring ──────────────────────────────────────────────────────────────────

// Score computes a 0.0–1.0 score for a result against expected criteria.
// Weights: findings 30%, CWE coverage 30%, tool usage 20%, completion 20%.
func Score(result Result, expected Expected) float64 {
	var score float64

	// Finding score (30%)
	if expected.MinFindings > 0 {
		findingRatio := float64(result.Findings) / float64(expected.MinFindings)
		if findingRatio > 1 {
			findingRatio = 1
		}
		score += findingRatio * 0.30
	} else {
		score += 0.30 // no requirement → full marks
	}

	// CWE coverage score (30%)
	if len(expected.RequiredCWEs) > 0 {
		cweSet := make(map[string]bool)
		for _, cwe := range result.CWEsFound {
			cweSet[cwe] = true
		}
		found := 0
		for _, required := range expected.RequiredCWEs {
			if cweSet[required] {
				found++
			}
		}
		score += (float64(found) / float64(len(expected.RequiredCWEs))) * 0.30
	} else {
		score += 0.30
	}

	// Tool usage score (20%)
	if len(expected.RequiredTools) > 0 {
		toolSet := make(map[string]bool)
		for _, tool := range result.ToolsUsed {
			toolSet[tool] = true
		}
		found := 0
		for _, required := range expected.RequiredTools {
			if toolSet[required] {
				found++
			}
		}
		score += (float64(found) / float64(len(expected.RequiredTools))) * 0.20
	} else {
		score += 0.20
	}

	// Completion score (20%) — no error and some observations
	if result.Error == "" {
		score += 0.10
	}
	if expected.MinObservations > 0 {
		obsRatio := float64(result.Observations) / float64(expected.MinObservations)
		if obsRatio > 1 {
			obsRatio = 1
		}
		score += obsRatio * 0.10
	} else if result.Observations > 0 {
		score += 0.10
	}

	return score
}

// ── built-in suites ──────────────────────────────────────────────────────────

func JuiceShopSuite(targetURL string) Suite {
	if targetURL == "" {
		targetURL = "http://localhost:3000"
	}
	return Suite{
		Name:        "juice-shop",
		Description: "OWASP Juice Shop v16+ benchmark suite",
		TargetURL:   targetURL,
		Cases: []Case{
			{
				Name: "recon", Prompt: fmt.Sprintf("Perform reconnaissance on %s: enumerate open ports, detect technologies, check HTTP headers", targetURL),
				Mode: "auto", TimeoutSec: 120,
				Expected: Expected{MinObservations: 2, RequiredTools: []string{"nmap", "http_headers"}},
			},
			{
				Name: "sqli-detection", Prompt: fmt.Sprintf("Assess %s for SQL injection vulnerabilities in login and search forms", targetURL),
				Mode: "auto", TimeoutSec: 180,
				Expected: Expected{MinFindings: 1, RequiredCWEs: []string{"CWE-89"}},
			},
			{
				Name: "xss-detection", Prompt: fmt.Sprintf("Assess %s for cross-site scripting vulnerabilities", targetURL),
				Mode: "auto", TimeoutSec: 180,
				Expected: Expected{MinFindings: 1, RequiredCWEs: []string{"CWE-79"}},
			},
			{
				Name: "auth-assessment", Prompt: fmt.Sprintf("Assess authentication security on %s including default credentials and session management", targetURL),
				Mode: "auto", TimeoutSec: 180,
				Expected: Expected{MinFindings: 1, RequiredTools: []string{"authenticate"}},
			},
			{
				Name: "full-assessment", Prompt: fmt.Sprintf("Perform a comprehensive security assessment of %s", targetURL),
				Mode: "auto", TimeoutSec: 300,
				Expected: Expected{MinFindings: 3, MinObservations: 5, RequiredTools: []string{"nmap", "http_headers"}},
			},
		},
	}
}

func DVWASuite(targetURL string) Suite {
	if targetURL == "" {
		targetURL = "http://localhost:8080"
	}
	return Suite{
		Name:        "dvwa",
		Description: "Damn Vulnerable Web Application benchmark suite",
		TargetURL:   targetURL,
		Cases: []Case{
			{
				Name: "recon", Prompt: fmt.Sprintf("Enumerate services and technologies on %s", targetURL),
				Mode: "auto", TimeoutSec: 120,
				Expected: Expected{MinObservations: 2},
			},
			{
				Name: "sqli", Prompt: fmt.Sprintf("Detect SQL injection vulnerabilities on %s", targetURL),
				Mode: "auto", TimeoutSec: 180,
				Expected: Expected{MinFindings: 1, RequiredCWEs: []string{"CWE-89"}},
			},
			{
				Name: "command-injection", Prompt: fmt.Sprintf("Detect command injection vulnerabilities on %s", targetURL),
				Mode: "auto", TimeoutSec: 180,
				Expected: Expected{MinFindings: 1, RequiredCWEs: []string{"CWE-78"}},
			},
		},
	}
}

func WebGoatSuite(targetURL string) Suite {
	if targetURL == "" {
		targetURL = "http://localhost:8080/WebGoat"
	}
	return Suite{
		Name:        "webgoat",
		Description: "OWASP WebGoat benchmark suite",
		TargetURL:   targetURL,
		Cases: []Case{
			{
				Name: "recon", Prompt: fmt.Sprintf("Perform reconnaissance on %s", targetURL),
				Mode: "auto", TimeoutSec: 120,
				Expected: Expected{MinObservations: 2},
			},
			{
				Name: "injection", Prompt: fmt.Sprintf("Detect injection vulnerabilities on %s", targetURL),
				Mode: "auto", TimeoutSec: 180,
				Expected: Expected{MinFindings: 1},
			},
		},
	}
}

func QuickSuite(targetURL string) Suite {
	return Suite{
		Name:        "quick",
		Description: "Quick smoke test: basic recon and header analysis",
		TargetURL:   targetURL,
		Cases: []Case{
			{
				Name: "smoke-recon", Prompt: fmt.Sprintf("Quick reconnaissance of %s: port scan and HTTP header analysis", targetURL),
				Mode: "default", TimeoutSec: 60,
				Expected: Expected{MinObservations: 1},
			},
		},
	}
}

// ── reports ──────────────────────────────────────────────────────────────────

// SuiteReport generates a Markdown report for a suite result.
func SuiteReport(sr SuiteResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Benchmark: %s\n\n", sr.Suite)
	fmt.Fprintf(&sb, "**Score:** %.1f%% | **Passed:** %d/%d | **Duration:** %s\n\n",
		sr.TotalScore*100, sr.Passed, sr.Passed+sr.Failed, sr.Duration.Round(time.Second))
	sb.WriteString("| Case | Score | Findings | Observations | CWEs | Duration | Status |\n")
	sb.WriteString("|------|-------|----------|--------------|------|----------|--------|\n")
	for _, r := range sr.Results {
		status := "✅"
		if !r.Passed {
			status = "❌"
		}
		fmt.Fprintf(&sb, "| %s | %.0f%% | %d | %d | %s | %s | %s |\n",
			r.Case, r.Score*100, r.Findings, r.Observations,
			strings.Join(r.CWEsFound, ","), r.Duration.Round(time.Second), status)
	}
	sb.WriteString("\n")
	for _, r := range sr.Results {
		if r.Error != "" {
			fmt.Fprintf(&sb, "**%s error:** %s\n\n", r.Case, r.Error)
		}
	}
	return sb.String()
}

// SuiteReportJSON returns the suite result as indented JSON.
func SuiteReportJSON(sr SuiteResult) ([]byte, error) {
	return json.MarshalIndent(sr, "", "  ")
}

// CompareResults detects regressions between a baseline and current run.
// A regression is flagged when score drops by more than the given threshold.
func CompareResults(baseline, current SuiteResult, threshold float64) []Regression {
	if threshold <= 0 {
		threshold = 0.1 // default 10% regression threshold
	}
	baselineMap := make(map[string]Result)
	for _, r := range baseline.Results {
		baselineMap[r.Case] = r
	}
	var regressions []Regression
	for _, cur := range current.Results {
		prev, ok := baselineMap[cur.Case]
		if !ok {
			continue
		}
		if prev.Score-cur.Score > threshold {
			regressions = append(regressions, Regression{
				Case:     cur.Case,
				Metric:   "score",
				Previous: prev.Score,
				Current:  cur.Score,
				Delta:    cur.Score - prev.Score,
			})
		}
		if prev.Findings > 0 && cur.Findings < prev.Findings {
			regressions = append(regressions, Regression{
				Case:     cur.Case,
				Metric:   "findings",
				Previous: float64(prev.Findings),
				Current:  float64(cur.Findings),
				Delta:    float64(cur.Findings - prev.Findings),
			})
		}
	}
	return regressions
}
