package evidence

import (
	"errors"
	"regexp"
	"strings"

	"rogue/internal/analysis"
	"rogue/internal/domain"
)

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
var cweID = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)

func (vault *Vault) ClassifyFinding(id, vector, cwe, remediation, reviewer string, cves []string) error {
	if strings.TrimSpace(reviewer) == "" || len(reviewer) > 128 {
		return errors.New("classification requires a named reviewer")
	}
	if cwe != "" && !cweID.MatchString(cwe) {
		return errors.New("invalid CWE identifier")
	}
	for _, id := range cves {
		if !cveID.MatchString(id) {
			return errors.New("invalid CVE identifier")
		}
	}
	score, err := analysis.BaseScore(vector)
	if err != nil {
		return err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	for index := range vault.findings {
		finding := &vault.findings[index]
		if finding.ID != id {
			continue
		}
		finding.CVSS = score
		finding.CVSSVector = vector
		finding.CWE = cwe
		finding.CVE = append([]string{}, cves...)
		finding.Remediation = remediation
		finding.ClassificationSource = "reviewed by " + reviewer
		finding.Severity = domain.SevInfo
		switch {
		case score >= 9:
			finding.Severity = domain.SevCritical
		case score >= 7:
			finding.Severity = domain.SevHigh
		case score >= 4:
			finding.Severity = domain.SevMedium
		case score > 0:
			finding.Severity = domain.SevLow
		}
		return nil
	}
	return errors.New("finding not found in this mission")
}
