// Package evidence stores mission observations and evidence-backed findings.
package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"rogue/internal/analysis"
	"rogue/internal/domain"
)

type Observation struct {
	ID, MissionID, TaskID, OperatorID, ToolCallID, Tool, Target string
	Input, Output                                               json.RawMessage
	Success                                                     bool
	Summary, Error                                              string
	StartedAt                                                   time.Time
	Duration                                                    time.Duration
	Artifact                                                    []byte
	ArtifactType                                                string
}

// Vault owns snapshots. Evidence backing does not assert exploit verification.
type Vault struct {
	mu           sync.RWMutex
	missionID    string
	observations []Observation
	findings     []domain.Finding
	credentials  []domain.Credential
	index        map[string]int
}

func New(missionID string) *Vault { return &Vault{missionID: missionID, index: make(map[string]int)} }
func cloneObservation(o Observation) Observation {
	o.Input = slices.Clone(o.Input)
	o.Output = slices.Clone(o.Output)
	o.Artifact = slices.Clone(o.Artifact)
	return o
}
func cloneFinding(f domain.Finding) domain.Finding {
	f.Evidence = slices.Clone(f.Evidence)
	f.CVE = slices.Clone(f.CVE)
	return f
}

func (v *Vault) Record(o Observation) (Observation, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if o.MissionID != v.missionID || o.TaskID == "" || o.OperatorID == "" || o.Tool == "" || o.ToolCallID == "" {
		return Observation{}, errors.New("evidence: incomplete or cross-mission provenance")
	}
	if !json.Valid(o.Input) || !json.Valid(o.Output) {
		return Observation{}, errors.New("evidence: input and output must be JSON")
	}
	for _, old := range v.observations {
		if old.TaskID == o.TaskID && old.ToolCallID == o.ToolCallID {
			return Observation{}, errors.New("evidence: duplicate tool call")
		}
	}
	o.ID = domain.ID()
	if o.StartedAt.IsZero() {
		o.StartedAt = time.Now().UTC()
	}
	v.observations = append(v.observations, cloneObservation(o))
	v.index[o.ID] = len(v.observations) - 1
	return cloneObservation(o), nil
}

func (v *Vault) Observation(id string) (Observation, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	index, found := v.index[id]
	if !found {
		return Observation{}, errors.New("observation not found in this mission")
	}
	return cloneObservation(v.observations[index]), nil
}

// CredentialSecret is only for an explicitly approved tool. Reports continue to
// use Credentials(), which never exposes secret values.
func (v *Vault) CredentialSecret(id string) (domain.Credential, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, credential := range v.credentials {
		if credential.ID == id {
			return credential, nil
		}
	}
	return domain.Credential{}, errors.New("credential not found in this mission")
}

func (v *Vault) AddFinding(f domain.Finding) (domain.Finding, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if f.MissionID != v.missionID || strings.TrimSpace(f.Title) == "" || len(f.Evidence) == 0 {
		return domain.Finding{}, errors.New("evidence: finding requires mission, title, and observation references")
	}
	switch f.Severity {
	case domain.SevCritical, domain.SevHigh, domain.SevMedium, domain.SevLow, domain.SevInfo:
	default:
		return domain.Finding{}, errors.New("evidence: invalid severity")
	}
	if math.IsNaN(f.CVSS) || math.IsInf(f.CVSS, 0) || f.CVSS < 0 || f.CVSS > 10 {
		return domain.Finding{}, errors.New("evidence: CVSS outside 0..10")
	}
	if f.CVSSVector != "" {
		score, err := analysis.BaseScore(f.CVSSVector)
		if err != nil {
			return domain.Finding{}, err
		}
		if score != f.CVSS {
			return domain.Finding{}, errors.New("CVSS score does not match its vector")
		}
	}
	ownerObserved := false
	for _, id := range f.Evidence {
		found := false
		for _, o := range v.observations {
			if o.ID == id && o.Success && o.Target == f.TargetID {
				found = true
				ownerObserved = ownerObserved || o.OperatorID == f.OperatorID
				break
			}
		}
		if !found {
			return domain.Finding{}, fmt.Errorf("evidence: observation %q is not successful evidence for this target and operator", id)
		}
	}
	if !ownerObserved {
		return domain.Finding{}, errors.New("evidence: finding owner has no supporting observation")
	}
	key := strings.ToLower(strings.Join(strings.Fields(f.Title), " "))
	for i := range v.findings {
		old := &v.findings[i]
		if old.TargetID == f.TargetID && strings.ToLower(strings.Join(strings.Fields(old.Title), " ")) == key {
			for _, ref := range f.Evidence {
				if !slices.Contains(old.Evidence, ref) {
					old.Evidence = append(old.Evidence, ref)
				}
			}
			return cloneFinding(*old), nil
		}
	}
	f.ID = domain.ID()
	f.CreatedAt = time.Now().UTC()
	v.findings = append(v.findings, cloneFinding(f))
	return cloneFinding(f), nil
}

func (v *Vault) Observations() []Observation {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]Observation, len(v.observations))
	for i, o := range v.observations {
		out[i] = cloneObservation(o)
	}
	return out
}
func (v *Vault) Findings() []domain.Finding {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]domain.Finding, len(v.findings))
	for i, f := range v.findings {
		out[i] = cloneFinding(f)
	}
	return out
}
func (v *Vault) FindingsBySeverity(sev domain.Severity) []domain.Finding {
	var out []domain.Finding
	for _, f := range v.Findings() {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

func redact(c domain.Credential) domain.Credential {
	c.SecretCaptured = c.Value != ""
	c.Value = ""
	return c
}
func (v *Vault) AddCredential(c domain.Credential) (domain.Credential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if c.MissionID != v.missionID || c.Type == "" || c.Value == "" {
		return domain.Credential{}, errors.New("evidence: credential requires matching mission, type, and value")
	}
	c.ID = domain.ID()
	v.credentials = append(v.credentials, c)
	return redact(c), nil
}

// Credentials is suitable for reports and model context; secrets stay internal.
func (v *Vault) Credentials() []domain.Credential {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]domain.Credential, len(v.credentials))
	for i, c := range v.credentials {
		out[i] = redact(c)
	}
	return out
}
func (v *Vault) Stats() (findings, credentials int) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.findings), len(v.credentials)
}
