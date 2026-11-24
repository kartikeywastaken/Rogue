// Package export provides multi-format evidence/report export and scanner import.
package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"rogue/internal/domain"
	"rogue/internal/engine"
)

const FormatVersion = "1.0.0"

// ExportMeta is included in structured export formats.
type ExportMeta struct {
	Format    string    `json:"format"`
	Version   string    `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	MissionID string    `json:"mission_id"`
}

// ── JSON export ──────────────────────────────────────────────────────────────

func ExportJSON(report engine.Report) ([]byte, error) {
	wrapper := struct {
		Meta   ExportMeta    `json:"meta"`
		Report engine.Report `json:"report"`
	}{
		Meta: ExportMeta{
			Format:     "json",
			Version:    FormatVersion,
			ExportedAt: time.Now().UTC(),
			MissionID:  report.Mission.ID,
		},
		Report: report,
	}
	return json.MarshalIndent(wrapper, "", "  ")
}

// ── SARIF 2.1.0 export ──────────────────────────────────────────────────────

type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}
type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   sarifMessage      `json:"message"`
	Locations []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]any   `json:"properties,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifLogical struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func severityToLevel(sev domain.Severity) string {
	switch sev {
	case domain.SevCritical, domain.SevHigh:
		return "error"
	case domain.SevMedium:
		return "warning"
	case domain.SevLow, domain.SevInfo:
		return "note"
	default:
		return "none"
	}
}

func ExportSARIF(report engine.Report) ([]byte, error) {
	var rules []sarifRule
	var results []sarifResult
	for _, f := range report.Evidence.Findings {
		ruleID := f.ID
		if f.CWE != "" {
			ruleID = f.CWE
		}
		props := make(map[string]string)
		if f.CWE != "" {
			props["cwe"] = f.CWE
		}
		rules = append(rules, sarifRule{
			ID:               ruleID,
			Name:             f.Title,
			ShortDescription: sarifMessage{Text: f.Description},
			Properties:       props,
		})
		rProps := map[string]any{
			"severity": string(f.Severity),
			"cvss":     f.CVSS,
		}
		if f.CVSSVector != "" {
			rProps["cvssVector"] = f.CVSSVector
		}
		if f.Remediation != "" {
			rProps["remediation"] = f.Remediation
		}
		if len(f.CVE) > 0 {
			rProps["cve"] = f.CVE
		}
		var locs []sarifLocation
		if f.TargetID != "" {
			locs = append(locs, sarifLocation{
				LogicalLocations: []sarifLogical{{Name: f.TargetID, Kind: "target"}},
			})
		}
		results = append(results, sarifResult{
			RuleID:     ruleID,
			Level:      severityToLevel(f.Severity),
			Message:    sarifMessage{Text: f.Title + ": " + f.Description},
			Locations:  locs,
			Properties: rProps,
		})
	}
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "rogue",
				Version:        FormatVersion,
				InformationURI: "https://github.com/rogue-security/rogue",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

// ── CSV export ───────────────────────────────────────────────────────────────

func ExportCSV(report engine.Report) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"ID", "Title", "Severity", "Target", "CWE", "CVSS", "CVE", "Remediation"})
	findings := append([]domain.Finding{}, report.Evidence.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})
	for _, f := range findings {
		_ = w.Write([]string{
			f.ID,
			f.Title,
			string(f.Severity),
			f.TargetID,
			f.CWE,
			fmt.Sprintf("%.1f", f.CVSS),
			strings.Join(f.CVE, "; "),
			f.Remediation,
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func severityRank(sev domain.Severity) int {
	switch sev {
	case domain.SevCritical:
		return 0
	case domain.SevHigh:
		return 1
	case domain.SevMedium:
		return 2
	case domain.SevLow:
		return 3
	default:
		return 4
	}
}

// ── HTML export ──────────────────────────────────────────────────────────────

func ExportHTML(report engine.Report) ([]byte, error) {
	var sb strings.Builder
	analysis := engine.Analyze(report)
	sb.WriteString(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ROGUE Assessment Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#e0e0e0;padding:2rem;max-width:1200px;margin:0 auto}
h1{color:#00ff88;margin-bottom:.5rem}h2{color:#00cc66;margin:1.5rem 0 .5rem;border-bottom:1px solid #333;padding-bottom:.25rem}
h3{color:#a0a0a0;margin:1rem 0 .5rem}
.meta{color:#888;margin-bottom:1.5rem}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600;text-transform:uppercase}
.critical{background:#ff0040;color:#fff}.high{background:#ff6600;color:#fff}.medium{background:#ffaa00;color:#000}.low{background:#0088ff;color:#fff}.info{background:#666;color:#fff}
table{width:100%;border-collapse:collapse;margin:.5rem 0}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #222}
th{background:#1a1a1a;color:#00ff88;font-weight:600}
tr:hover{background:#111}
.stat{display:inline-block;margin-right:2rem}.stat-val{font-size:1.5em;color:#00ff88}.stat-label{color:#888;font-size:.85em}
.finding{background:#111;border:1px solid #222;border-radius:8px;padding:1rem;margin:.5rem 0}
.remediation{color:#00cc66;margin-top:.5rem;font-style:italic}
</style></head><body>
`)
	sb.WriteString(fmt.Sprintf("<h1>ROGUE Assessment Report</h1>\n<p class=\"meta\">Mission: %s | Status: %s | %s</p>\n",
		html.EscapeString(report.Mission.ID),
		html.EscapeString(string(report.Mission.Status)),
		html.EscapeString(report.Mission.CreatedAt.Format(time.RFC3339))))

	// Summary stats
	sb.WriteString("<div style=\"margin:1rem 0\">\n")
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-val\">%d</div><div class=\"stat-label\">Observations</div></div>\n",
		analysis.SuccessfulObservations+analysis.FailedObservations))
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-val\">%d</div><div class=\"stat-label\">Findings</div></div>\n",
		len(report.Evidence.Findings)))
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-val\">%d</div><div class=\"stat-label\">Evidence-linked</div></div>\n",
		analysis.FindingsWithEvidence))
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-val\">%d</div><div class=\"stat-label\">CVE References</div></div>\n",
		analysis.CVECandidates))
	sb.WriteString("</div>\n")

	// Severity breakdown
	if len(analysis.SeverityCounts) > 0 {
		sb.WriteString("<h2>Severity Distribution</h2>\n<p>")
		for _, sev := range []domain.Severity{domain.SevCritical, domain.SevHigh, domain.SevMedium, domain.SevLow, domain.SevInfo} {
			if count, ok := analysis.SeverityCounts[sev]; ok && count > 0 {
				sb.WriteString(fmt.Sprintf("<span class=\"badge %s\">%s: %d</span> ", sev, sev, count))
			}
		}
		sb.WriteString("</p>\n")
	}

	// Findings table
	sb.WriteString("<h2>Findings</h2>\n")
	if len(report.Evidence.Findings) == 0 {
		sb.WriteString("<p>No structured findings recorded.</p>\n")
	} else {
		sb.WriteString("<table><tr><th>Severity</th><th>Title</th><th>Target</th><th>CWE</th><th>CVSS</th><th>Remediation</th></tr>\n")
		for _, f := range report.Evidence.Findings {
			sb.WriteString(fmt.Sprintf("<tr><td><span class=\"badge %s\">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%.1f</td><td>%s</td></tr>\n",
				f.Severity, f.Severity,
				html.EscapeString(f.Title),
				html.EscapeString(f.TargetID),
				html.EscapeString(f.CWE),
				f.CVSS,
				html.EscapeString(f.Remediation)))
		}
		sb.WriteString("</table>\n")
	}

	// Finding detail cards
	for _, f := range report.Evidence.Findings {
		sb.WriteString(fmt.Sprintf("<div class=\"finding\"><h3><span class=\"badge %s\">%s</span> %s</h3>\n",
			f.Severity, f.Severity, html.EscapeString(f.Title)))
		sb.WriteString(fmt.Sprintf("<p>%s</p>\n", html.EscapeString(f.Description)))
		sb.WriteString(fmt.Sprintf("<p>Target: %s | Evidence: %s</p>\n",
			html.EscapeString(f.TargetID), html.EscapeString(strings.Join(f.Evidence, ", "))))
		if f.CVSSVector != "" {
			sb.WriteString(fmt.Sprintf("<p>CVSS: %.1f (%s)</p>\n", f.CVSS, html.EscapeString(f.CVSSVector)))
		}
		if len(f.CVE) > 0 {
			sb.WriteString(fmt.Sprintf("<p>CVE: %s</p>\n", html.EscapeString(strings.Join(f.CVE, ", "))))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("<p class=\"remediation\">Remediation: %s</p>\n", html.EscapeString(f.Remediation)))
		}
		sb.WriteString("</div>\n")
	}

	// Observations
	sb.WriteString("<h2>Observation Index</h2>\n<table><tr><th>ID</th><th>Tool</th><th>Target</th><th>Success</th><th>Summary</th></tr>\n")
	for _, o := range report.Evidence.Observations {
		sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%t</td><td>%s</td></tr>\n",
			html.EscapeString(o.ID), html.EscapeString(o.Tool),
			html.EscapeString(o.Target), o.Success, html.EscapeString(o.Summary)))
	}
	sb.WriteString("</table>\n")

	// Limitations
	sb.WriteString("<h2>Limitations</h2><ul>\n")
	for _, l := range analysis.Limitations {
		sb.WriteString(fmt.Sprintf("<li>%s</li>\n", html.EscapeString(l)))
	}
	sb.WriteString("</ul>\n")

	sb.WriteString(fmt.Sprintf("<footer style=\"margin-top:2rem;padding-top:1rem;border-top:1px solid #333;color:#666;font-size:.8em\">Generated by ROGUE v%s at %s</footer>\n",
		FormatVersion, time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("</body></html>")
	return []byte(sb.String()), nil
}

// ── Nmap XML import ──────────────────────────────────────────────────────────

type ImportedHost struct {
	Address  string            `json:"address"`
	Hostname string            `json:"hostname,omitempty"`
	Status   string            `json:"status"`
	Ports    []ImportedPort    `json:"ports,omitempty"`
	OS       string            `json:"os,omitempty"`
}

type ImportedPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Product  string `json:"product,omitempty"`
	CPE      string `json:"cpe,omitempty"`
}

// nmapRun is the root of Nmap XML output.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}
type nmapHost struct {
	Status    nmapStatus      `xml:"status"`
	Addresses []nmapAddress   `xml:"address"`
	Hostnames nmapHostnames   `xml:"hostnames"`
	Ports     nmapPorts       `xml:"ports"`
	OS        nmapOS          `xml:"os"`
}
type nmapStatus struct {
	State string `xml:"state,attr"`
}
type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}
type nmapHostname struct {
	Name string `xml:"name,attr"`
}
type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}
type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}
type nmapState struct {
	State string `xml:"state,attr"`
}
type nmapService struct {
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Version string   `xml:"version,attr"`
	CPEs    []string `xml:"cpe"`
}
type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}
type nmapOSMatch struct {
	Name string `xml:"name,attr"`
}

func ImportNmapXML(data []byte) ([]ImportedHost, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}
	var hosts []ImportedHost
	for _, h := range run.Hosts {
		host := ImportedHost{Status: h.Status.State}
		for _, addr := range h.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				host.Address = addr.Addr
				break
			}
		}
		if host.Address == "" {
			for _, addr := range h.Addresses {
				host.Address = addr.Addr
				break
			}
		}
		if len(h.Hostnames.Hostnames) > 0 {
			host.Hostname = h.Hostnames.Hostnames[0].Name
		}
		if len(h.OS.Matches) > 0 {
			host.OS = h.OS.Matches[0].Name
		}
		for _, p := range h.Ports.Ports {
			ip := ImportedPort{
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
			}
			if len(p.Service.CPEs) > 0 {
				ip.CPE = p.Service.CPEs[0]
			}
			host.Ports = append(host.Ports, ip)
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

// ── Nuclei JSONL import ──────────────────────────────────────────────────────

type ImportedFinding struct {
	TemplateID  string `json:"template_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched_at"`
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
}

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
		Classification struct {
			CWEID string  `json:"cwe-id"`
			CVSSScore float64 `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
}

func ImportNucleiJSON(data []byte) ([]ImportedFinding, error) {
	var findings []ImportedFinding
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var nr nucleiResult
		if err := json.Unmarshal(line, &nr); err != nil {
			continue // skip malformed lines
		}
		ref := ""
		if len(nr.Info.Reference) > 0 {
			ref = strings.Join(nr.Info.Reference, "; ")
		}
		findings = append(findings, ImportedFinding{
			TemplateID:  nr.TemplateID,
			Name:        nr.Info.Name,
			Severity:    nr.Info.Severity,
			Host:        nr.Host,
			MatchedAt:   nr.MatchedAt,
			Description: nr.Info.Description,
			Reference:   ref,
			CWE:         nr.Info.Classification.CWEID,
			CVSS:        nr.Info.Classification.CVSSScore,
		})
	}
	return findings, nil
}
