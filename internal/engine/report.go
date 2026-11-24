package engine

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"rogue/internal/domain"
	"rogue/internal/evidence"
	"rogue/internal/mission"
	"rogue/internal/target"
)

type Analysis struct {
	AccessPaths                                                      []AccessPath
	Priorities                                                       []string
	Candidates                                                       []target.Candidate
	ToolCounts                                                       map[string]int
	SeverityCounts                                                   map[domain.Severity]int
	SuccessfulObservations, FailedObservations, FindingsWithEvidence int
	CVECandidates                                                    int
	Limitations                                                      []string
}

// Analyze counts inspectable facts. It never promotes model prose or a CVE
// search hit into a vulnerability or invents a CVSS score.
func Analyze(report Report) Analysis {
	analysis := Analysis{ToolCounts: make(map[string]int), SeverityCounts: make(map[domain.Severity]int), CVECandidates: len(report.Targets.References), Limitations: []string{
		"Operator task summaries are model-generated analysis, not verified findings.",
		"CVE references require target applicability checks; no exploit execution is inferred.",
		"Approved lab tools verify bounded endpoint behavior; arbitrary privilege escalation, persistence deployment and external transfer are unsupported.",
		"Shared model context is bounded; the encrypted vault retains the original observations.",
	}}
	observed := make(map[string]evidence.Observation)
	for _, observation := range report.Evidence.Observations {
		analysis.ToolCounts[observation.Tool]++
		observed[observation.ID] = observation
		if observation.Success {
			analysis.SuccessfulObservations++
		} else {
			analysis.FailedObservations++
		}
	}
	for _, finding := range report.Evidence.Findings {
		analysis.SeverityCounts[finding.Severity]++
		valid := len(finding.Evidence) > 0
		for _, id := range finding.Evidence {
			observation, found := observed[id]
			valid = valid && found && observation.Success && observation.Target == finding.TargetID
		}
		if valid {
			analysis.FindingsWithEvidence++
			if finding.Remediation != "" && !slices.Contains(analysis.Priorities, finding.Remediation) {
				analysis.Priorities = append(analysis.Priorities, finding.Remediation)
			}
		}
	}
	analysis.AccessPaths = observedPaths(report)
	analysis.Candidates = target.CandidateMatches(report.Targets)
	return analysis
}

// Markdown exports the same redacted report as JSON. It is generated from saved
// state, so exporting a report never makes another provider request.
func (report Report) Markdown() string {
	var text strings.Builder
	fmt.Fprintf(&text, "# ROGUE assessment %s\n\nStatus: %s\n\nObjective: %s\n\n", report.Mission.ID, report.Mission.Status, plain(report.Mission.Objective))
	analysis := report.Analysis
	if analysis.ToolCounts == nil {
		analysis = Analyze(report)
	}
	fmt.Fprintf(&text, "## Evidence summary\n\n%d successful observations; %d failed observations; %d evidence-linked findings; %d CVE references.\n\n", analysis.SuccessfulObservations, analysis.FailedObservations, analysis.FindingsWithEvidence, analysis.CVECandidates)
	findings := append([]domain.Finding{}, report.Evidence.Findings...)
	sort.SliceStable(findings, func(i, j int) bool { return severityRank(findings[i].Severity) < severityRank(findings[j].Severity) })
	text.WriteString("## Findings\n\n")
	if len(findings) == 0 {
		text.WriteString("No structured findings recorded. This does not establish that the target is secure.\n\n")
	}
	for _, finding := range findings {
		fmt.Fprintf(&text, "### %s (%s)\n\nTarget: %s\n\n%s\n\nEvidence: %s\n\nRemediation: %s\n\n", plain(finding.Title), finding.Severity, plain(finding.TargetID), plain(finding.Description), strings.Join(finding.Evidence, ", "), plain(finding.Remediation))
		if finding.CVSSVector != "" {
			fmt.Fprintf(&text, "CVSS: %.1f (%s)\n\n", finding.CVSS, plain(finding.CVSSVector))
		}
		if finding.CWE != "" {
			fmt.Fprintf(&text, "CWE: %s\n\n", plain(finding.CWE))
		}
		if len(finding.CVE) > 0 {
			fmt.Fprintf(&text, "Reviewed CVE associations: %s\n\n", plain(strings.Join(finding.CVE, ", ")))
		}
		if finding.ClassificationSource != "" {
			fmt.Fprintf(&text, "Classification source: %s\n\n", plain(finding.ClassificationSource))
		}
	}
	text.WriteString("## Observed access paths\n\n")
	if len(analysis.AccessPaths) == 0 {
		text.WriteString("No confirmed authenticated access sequence recorded.\n\n")
	}
	for _, path := range analysis.AccessPaths {
		fmt.Fprintf(&text, "%s — %s\n\n", plain(path.Target), plain(path.Outcome))
		for _, step := range path.Steps {
			fmt.Fprintf(&text, "- %s (evidence: %s)\n", plain(step.Description), strings.Join(step.EvidenceIDs, ", "))
		}
		text.WriteString("\nThis sequence does not by itself establish an exploit.\n\n")
	}
	text.WriteString("## Operator reviews (unverified model text)\n\n")
	for _, task := range report.Mission.Tasks {
		fmt.Fprintf(&text, "### %s — %s\n\nTask: %s\n\n", task.Archetype, task.Status, plain(task.Title))
		if task.Status == mission.TaskCompleted {
			fmt.Fprintf(&text, "%s\n\n", plain(task.Result))
		} else {
			fmt.Fprintf(&text, "%s\n\n", plain(task.Error))
		}
	}
	text.WriteString("## Observation index\n\n")
	for _, observation := range report.Evidence.Observations {
		fmt.Fprintf(&text, "- %s · %s · success=%t · %s · %s\n", observation.ID, observation.Tool, observation.Success, plain(observation.Target), plain(observation.Summary))
	}
	text.WriteString("\n## Limitations\n\n")
	for _, limitation := range analysis.Limitations {
		fmt.Fprintf(&text, "- %s\n", limitation)
	}
	return text.String()
}

func plain(value string) string {
	// Export remote/model text as literal text, avoiding executable links/images
	// and accidental report headings from an untrusted response.
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\\", "\\\\", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "#", "\\#", "`", "\\`", "\r", "").Replace(value)
}

func severityRank(severity domain.Severity) int {
	switch severity {
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
