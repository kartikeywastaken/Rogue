package target

import "strings"

type Candidate struct {
	Host, CVE, Product, Version, Status, Reason string
	Evidence                                    []string
}

// CandidateMatches is triage, not applicability confirmation. Published text
// can mention unaffected versions; deployment and range conditions need review.
func CandidateMatches(snapshot Snapshot) []Candidate {
	var candidates []Candidate
	for _, host := range snapshot.Hosts {
		for _, service := range host.Services {
			if len(service.Product) < 3 || service.Version == "" {
				continue
			}
			for _, reference := range snapshot.References {
				text := strings.ToLower(reference.Description)
				if !strings.Contains(text, strings.ToLower(service.Product)) || !strings.Contains(text, strings.ToLower(service.Version)) {
					continue
				}
				evidence := append([]string{}, service.Evidence...)
				evidence = append(evidence, reference.Evidence...)
				candidates = append(candidates, Candidate{Host: host.Name, CVE: reference.ID, Product: service.Product, Version: service.Version, Status: "requires_review", Reason: "Observed product/version strings occur in the published description; affected ranges, platform preconditions and exploitability remain unverified", Evidence: evidence})
				if len(candidates) == 64 {
					return candidates
				}
			}
		}
	}
	return candidates
}
