package engine

import "errors"

// Classification is an explicit review, never a model's score guess. A reviewed
// CVE association does not claim successful exploitation.
func (harness *Harness) ClassifyFinding(missionID, findingID, vector, cwe, remediation, reviewer string, cves []string) error {
	state, err := harness.activeRun(missionID)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	for _, id := range cves {
		found := false
		for _, reference := range state.Targets.Snapshot().References {
			found = found || reference.ID == id
		}
		if !found {
			return errors.New("reviewed CVE must exist in this mission's reference catalog")
		}
	}
	if err = state.Evidence.ClassifyFinding(findingID, vector, cwe, remediation, reviewer, cves); err != nil {
		return err
	}
	return errors.Join(state.publish("control", "finding.classified", findingID+" by "+reviewer), state.save())
}
