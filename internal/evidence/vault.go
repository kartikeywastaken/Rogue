// Package evidence provides the EvidenceVault: a central, concurrency-safe
// store for findings and credentials discovered during a mission.
package evidence

import (
	"sync"
	"time"

	"rogue/internal/domain"
)

// Vault stores findings and credentials.
type Vault struct {
	mu          sync.RWMutex
	findings    []domain.Finding
	credentials []domain.Credential
}

// New creates an empty vault.
func New() *Vault { return &Vault{} }

// AddFinding stores a finding, assigning an ID and timestamp if empty.
func (v *Vault) AddFinding(f domain.Finding) domain.Finding {
	v.mu.Lock()
	defer v.mu.Unlock()
	if f.ID == "" {
		f.ID = domain.ID()
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now()
	}
	v.findings = append(v.findings, f)
	return f
}

// Findings returns a copy of all stored findings.
func (v *Vault) Findings() []domain.Finding {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]domain.Finding, len(v.findings))
	copy(out, v.findings)
	return out
}

// FindingsBySeverity returns findings matching the given severity.
func (v *Vault) FindingsBySeverity(sev domain.Severity) []domain.Finding {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var out []domain.Finding
	for _, f := range v.findings {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

// AddCredential stores a credential, assigning an ID if empty.
func (v *Vault) AddCredential(c domain.Credential) domain.Credential {
	v.mu.Lock()
	defer v.mu.Unlock()
	if c.ID == "" {
		c.ID = domain.ID()
	}
	v.credentials = append(v.credentials, c)
	return c
}

// Credentials returns a copy of all stored credentials.
func (v *Vault) Credentials() []domain.Credential {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]domain.Credential, len(v.credentials))
	copy(out, v.credentials)
	return out
}

// Stats returns a quick summary of vault contents.
func (v *Vault) Stats() (findings, credentials int) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.findings), len(v.credentials)
}
