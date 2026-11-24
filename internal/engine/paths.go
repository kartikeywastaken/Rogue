package engine

import "encoding/json"

type AccessStep struct {
	Description string
	EvidenceIDs []string
}
type AccessPath struct {
	Target, Outcome  string
	Steps            []AccessStep
	ExploitConfirmed bool
}

// Only responses demonstrating access establish path edges. Co-located findings
// and CVE keyword matches are not evidence of an exploitation chain.
func observedPaths(report Report) []AccessPath {
	var paths []AccessPath
	for _, observation := range report.Evidence.Observations {
		if observation.Tool != "session_check" || !observation.Success {
			continue
		}
		var result struct {
			Data struct {
				Confirmed    bool   `json:"authenticated_access_confirmed"`
				CredentialID string `json:"credential_id"`
			}
		}
		if json.Unmarshal(observation.Output, &result) != nil || !result.Data.Confirmed {
			continue
		}
		path := AccessPath{Target: observation.Target, Outcome: "Provided session accepted on an endpoint that denied the unauthenticated baseline", Steps: []AccessStep{{Description: "Unauthenticated baseline denied; session-authenticated GET accepted", EvidenceIDs: []string{observation.ID}}}}
		for _, credential := range report.Evidence.Credentials {
			if credential.ID == result.Data.CredentialID && credential.Source != "" {
				path.Steps = append([]AccessStep{{Description: "Lab authentication returned a captured session credential", EvidenceIDs: []string{credential.Source}}}, path.Steps...)
			}
		}
		paths = append(paths, path)
	}
	return paths
}
