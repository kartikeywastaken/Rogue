package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rogue/internal/arsenal"
	"rogue/internal/engine"
	"rogue/internal/export"
	"rogue/internal/llm"
	"rogue/internal/operator"
	"rogue/internal/storage"
	"rogue/internal/telemetry"
)

// ── mission operations ───────────────────────────────────────────────────────

func runExportMission(harness *engine.Harness, id, format, outputPath string) error {
	report, err := harness.Report(id)
	if err != nil {
		return err
	}
	var data []byte
	switch format {
	case "markdown":
		data = []byte(report.Markdown())
	default:
		data, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
	}
	if outputPath == "-" || outputPath == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(outputPath, data, 0600)
}

func runDeleteMission(store *storage.Store, id string) error {
	if _, err := store.Load(id); err != nil {
		return fmt.Errorf("mission %s not found: %w", id, err)
	}
	dir := stateDir()
	path := filepath.Join(dir, id+".state")
	if err := os.Remove(path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "deleted mission %s\n", id)
	return nil
}

func stateDir() string {
	dir := os.Getenv("ROGUE_STATE_DIR")
	if dir == "" {
		dir = ".rogue"
	}
	return dir
}

func runMissionStatus(harness *engine.Harness, id string) error {
	report, err := harness.Report(id)
	if err != nil {
		return err
	}
	type taskSummary struct {
		ID        string `json:"id"`
		Role      string `json:"role"`
		Status    string `json:"status"`
		Title     string `json:"title"`
		Operator  string `json:"operator,omitempty"`
	}
	var tasks []taskSummary
	for _, t := range report.Mission.Tasks {
		tasks = append(tasks, taskSummary{ID: t.ID, Role: string(t.Archetype), Status: string(t.Status), Title: t.Title, Operator: t.OperatorID})
	}
	status := map[string]any{
		"mission_id":    report.Mission.ID,
		"status":        report.Mission.Status,
		"objective":     report.Mission.Objective,
		"created_at":    report.Mission.CreatedAt,
		"tasks":         tasks,
		"task_count":    len(tasks),
		"observations":  report.Analysis.SuccessfulObservations + report.Analysis.FailedObservations,
		"findings":      report.Analysis.FindingsWithEvidence,
		"severity":      report.Analysis.SeverityCounts,
		"tools_used":    report.Analysis.ToolCounts,
		"spending":      report.Spending,
		"operators":     len(report.Operators),
		"messages":      len(report.Messages),
		"cve_candidates": report.Analysis.CVECandidates,
	}
	return printJSON(status)
}

// ── configuration ────────────────────────────────────────────────────────────

func runShowConfig() error {
	summary := telemetry.SummarizeConfig()
	return printJSON(summary)
}

func runValidateConfig() error {
	var errs []string
	if _, err := loadOptions(); err != nil {
		errs = append(errs, "options: "+err.Error())
	}
	if _, err := llm.LoadConfig(os.Getenv); err != nil {
		errs = append(errs, "provider: "+err.Error())
	}
	if _, err := openStore(); err != nil {
		errs = append(errs, "store: "+err.Error())
	}
	reg := newRegistry()
	result := map[string]any{
		"valid":      len(errs) == 0,
		"errors":     errs,
		"tool_count": len(reg.All()),
		"config":     telemetry.SummarizeConfig(),
		"build":      telemetry.DefaultBuildInfo(),
	}
	return printJSON(result)
}

// ── tool management ──────────────────────────────────────────────────────────

func runToolInfo(registry *arsenal.Registry, name string) error {
	tool := registry.Get(name)
	if tool == nil {
		return fmt.Errorf("unknown tool %q", name)
	}
	status := "available"
	if tool.Available != nil {
		if err := tool.Available(); err != nil {
			status = err.Error()
		}
	}
	info := map[string]any{
		"name":           tool.Name,
		"category":       tool.Category,
		"description":    tool.Description,
		"parameters":     tool.Parameters,
		"availability":   status,
		"lab_only":       tool.LabOnly,
		"internal":       tool.Internal,
		"sensitive_args": tool.SensitiveArgs,
	}
	return printJSON(info)
}

// ── presets ───────────────────────────────────────────────────────────────────

type Preset struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Scope         []string `json:"scope,omitempty"`
	Mode          string   `json:"mode"`
	MaxIterations int      `json:"max_iterations"`
	Timeout       string   `json:"timeout"`
	Tools         []string `json:"tools,omitempty"`
	Lab           bool     `json:"lab"`
}

func builtinPresets() []Preset {
	return []Preset{
		{Name: "web-quick", Description: "Quick web application scan: DNS, ports, headers, technology detection", Mode: "auto", MaxIterations: 10, Timeout: "2m"},
		{Name: "web-full", Description: "Full web assessment: recon, scanning, vulnerability detection, authentication testing", Mode: "auto", MaxIterations: 20, Timeout: "5m", Lab: true},
		{Name: "api-assessment", Description: "API security assessment: endpoint discovery, authentication, injection testing", Mode: "auto", MaxIterations: 15, Timeout: "3m"},
		{Name: "infrastructure", Description: "Infrastructure assessment: network mapping, service enumeration, CVE correlation", Mode: "auto", MaxIterations: 20, Timeout: "5m", Tools: []string{"nmap", "dig", "curl"}},
		{Name: "recon-only", Description: "Passive reconnaissance only: DNS, WHOIS, header analysis, technology fingerprinting", Mode: "default", MaxIterations: 8, Timeout: "2m"},
		{Name: "stealth", Description: "Minimal footprint assessment with OPSEC constraints", Mode: "default", MaxIterations: 10, Timeout: "3m"},
	}
}

func runListPresets() error {
	return printJSON(builtinPresets())
}

// ── report operations ────────────────────────────────────────────────────────

func runMergeReports(harness *engine.Harness, ids []string, format string) error {
	if len(ids) == 0 {
		return errors.New("at least one mission ID required")
	}
	type mergedReport struct {
		MissionIDs  []string              `json:"mission_ids"`
		MergedAt    time.Time             `json:"merged_at"`
		Findings    []mergedFinding       `json:"findings"`
		Summary     map[string]int        `json:"summary"`
	}
	type finding = mergedFinding
	var allFindings []mergedFinding
	severityCounts := make(map[string]int)
	for _, id := range ids {
		report, err := harness.Report(id)
		if err != nil {
			return fmt.Errorf("loading mission %s: %w", id, err)
		}
		for _, f := range report.Evidence.Findings {
			allFindings = append(allFindings, mergedFinding{
				MissionID:   id,
				ID:          f.ID,
				Title:       f.Title,
				Severity:    string(f.Severity),
				Target:      f.TargetID,
				CWE:         f.CWE,
				CVSS:        f.CVSS,
				Remediation: f.Remediation,
			})
			severityCounts[string(f.Severity)]++
		}
	}
	merged := mergedReport{
		MissionIDs: ids,
		MergedAt:   time.Now().UTC(),
		Findings:   allFindings,
		Summary:    severityCounts,
	}
	if format == "markdown" {
		var sb strings.Builder
		fmt.Fprintf(&sb, "# Merged Assessment Report\n\nMissions: %s\nMerged: %s\n\n", strings.Join(ids, ", "), merged.MergedAt.Format(time.RFC3339))
		fmt.Fprintf(&sb, "## Summary\n\n")
		for sev, count := range severityCounts {
			fmt.Fprintf(&sb, "- %s: %d\n", sev, count)
		}
		fmt.Fprintf(&sb, "\n## Findings (%d total)\n\n", len(allFindings))
		for _, f := range allFindings {
			fmt.Fprintf(&sb, "### %s (%s)\n\nMission: %s | Target: %s | CWE: %s | CVSS: %.1f\n\n%s\n\n", f.Title, f.Severity, f.MissionID, f.Target, f.CWE, f.CVSS, f.Remediation)
		}
		_, err := fmt.Fprint(os.Stdout, sb.String())
		return err
	}
	return printJSON(merged)
}

type mergedFinding struct {
	MissionID   string  `json:"mission_id"`
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	Target      string  `json:"target"`
	CWE         string  `json:"cwe"`
	CVSS        float64 `json:"cvss"`
	Remediation string  `json:"remediation"`
}

// ── operator info ────────────────────────────────────────────────────────────

func runListOperators() error {
	profiles := operator.Profiles()
	type profile struct {
		Archetype string   `json:"archetype"`
		Callsign  string   `json:"callsign"`
		Phase     string   `json:"phase"`
		ToolCats  []string `json:"tool_categories"`
	}
	var list []profile
	for _, p := range profiles {
		list = append(list, profile{Archetype: string(p.Archetype), Callsign: p.Callsign, Phase: string(p.Phase), ToolCats: p.ToolCats})
	}
	return printJSON(list)
}

// ── export helpers ────────────────────────────────────────────────────────────

// exportReport renders a report in the requested format and writes to outputPath
// (or stdout if outputPath is "-" or empty).
func exportReport(report engine.Report, format, outputPath string) error {
	var (
		data []byte
		err  error
	)
	switch format {
	case "sarif":
		data, err = export.ExportSARIF(report)
	case "csv":
		data, err = export.ExportCSV(report)
	case "html":
		data, err = export.ExportHTML(report)
	case "markdown":
		data = []byte(report.Markdown())
	default: // json
		data, err = export.ExportJSON(report)
	}
	if err != nil {
		return err
	}
	if outputPath == "" || outputPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(outputPath, data, 0600)
}

// splitCSV splits a comma-separated string, trimming whitespace and skipping empties.
func splitCSV(raw string) []string {
	var result []string
	for _, part := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			result = append(result, s)
		}
	}
	return result
}
