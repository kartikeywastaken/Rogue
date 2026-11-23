package evidence

import (
	"errors"
	"slices"

	"rogue/internal/domain"
)

// PrivateCredential and PrivateSnapshot are exclusively for encrypted storage,
// never reports or model context. Public exports remain redacted.
type PrivateCredential struct {
	Metadata domain.Credential
	Secret   string
}
type Snapshot struct {
	MissionID    string
	Observations []Observation
	Findings     []domain.Finding
	Credentials  []PrivateCredential
}

func (vault *Vault) PrivateSnapshot() Snapshot {
	vault.mu.RLock()
	defer vault.mu.RUnlock()
	snapshot := Snapshot{MissionID: vault.missionID}
	for _, observation := range vault.observations {
		snapshot.Observations = append(snapshot.Observations, cloneObservation(observation))
	}
	for _, finding := range vault.findings {
		snapshot.Findings = append(snapshot.Findings, cloneFinding(finding))
	}
	for _, credential := range vault.credentials {
		snapshot.Credentials = append(snapshot.Credentials, PrivateCredential{Metadata: redact(credential), Secret: credential.Value})
	}
	return snapshot
}
func Restore(snapshot Snapshot) (*Vault, error) {
	if snapshot.MissionID == "" {
		return nil, errors.New("evidence: saved mission missing")
	}
	vault := New(snapshot.MissionID)
	ids := map[string]bool{}
	calls := map[string]bool{}
	for _, observation := range snapshot.Observations {
		if observation.ID == "" || ids[observation.ID] || calls[observation.TaskID+"/"+observation.ToolCallID] {
			return nil, errors.New("evidence: duplicate saved observation")
		}
		originalID := observation.ID
		if _, err := vault.Record(observation); err != nil {
			return nil, err
		}
		vault.observations[len(vault.observations)-1].ID = originalID
		ids[originalID] = true
		calls[observation.TaskID+"/"+observation.ToolCallID] = true
	}
	for _, finding := range snapshot.Findings {
		if finding.ID == "" || ids[finding.ID] {
			return nil, errors.New("evidence: duplicate saved finding")
		}
		id, created := finding.ID, finding.CreatedAt
		count := len(vault.findings)
		stored, err := vault.AddFinding(finding)
		if err != nil {
			return nil, err
		}
		if len(vault.findings) != count+1 || stored.ID != vault.findings[len(vault.findings)-1].ID {
			return nil, errors.New("evidence: conflicting saved finding")
		}
		vault.findings[len(vault.findings)-1].ID = id
		vault.findings[len(vault.findings)-1].CreatedAt = created
		ids[id] = true
	}
	for _, item := range snapshot.Credentials {
		credential := item.Metadata
		credential.Value = item.Secret
		if credential.ID == "" || ids[credential.ID] || credential.MissionID != snapshot.MissionID || credential.Type == "" || credential.Value == "" {
			return nil, errors.New("evidence: invalid saved credential")
		}
		ids[credential.ID] = true
		vault.credentials = append(vault.credentials, credential)
	}
	return vault, nil
}

// PublicSnapshot excludes raw credentials and raw network bodies/headers. The
// protected private snapshot is the source for detailed authorized inspection.
type PublicSnapshot struct {
	MissionID    string
	Observations []Observation
	Findings     []domain.Finding
	Credentials  []domain.Credential
}

func (vault *Vault) PublicSnapshot() PublicSnapshot {
	snapshot := PublicSnapshot{MissionID: vault.missionID, Observations: vault.Observations(), Findings: vault.Findings(), Credentials: vault.Credentials()}
	for index := range snapshot.Observations {
		snapshot.Observations[index].Input = nil
		snapshot.Observations[index].Output = nil
		snapshot.Observations[index].Artifact = nil
	}
	snapshot.Observations = slices.Clone(snapshot.Observations)
	return snapshot
}
