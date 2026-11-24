// Package domain defines the core types shared across the ROGUE harness.
package domain

import (
	"crypto/rand"
	"fmt"
	"time"
)

// ID returns a short random hex identifier.
func ID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ── enums ────────────────────────────────────────────────────────────────────

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

type KillChainPhase string

const (
	PhaseRecon     KillChainPhase = "recon"
	PhaseWeaponize KillChainPhase = "weaponize"
	PhaseDeliver   KillChainPhase = "deliver"
	PhaseExploit   KillChainPhase = "exploit"
	PhaseInstall   KillChainPhase = "install"
	PhaseC2        KillChainPhase = "c2"
	PhaseActions   KillChainPhase = "actions"
)

type Archetype string

const (
	ArchRecon       Archetype = "recon"
	ArchScanner     Archetype = "scanner"
	ArchExploiter   Archetype = "exploiter"
	ArchInfiltrator Archetype = "infiltrator"
	ArchExfiltrator Archetype = "exfiltrator"
	ArchGhost       Archetype = "ghost"
	ArchCoordinator Archetype = "coordinator"
	ArchAnalyst     Archetype = "analyst"
)

type OperatorState string

const (
	StateIdle      OperatorState = "idle"
	StateTasked    OperatorState = "tasked"
	StateExecuting OperatorState = "executing"
	StateCooldown  OperatorState = "cooldown"
	StateBurned    OperatorState = "burned"
)

type TargetStatus string

const (
	StatusDiscovered TargetStatus = "discovered"
	StatusScanning   TargetStatus = "scanning"
	StatusVulnerable TargetStatus = "vulnerable"
	StatusExploited  TargetStatus = "exploited"
	StatusOwned      TargetStatus = "owned"
)

// ── domain objects ───────────────────────────────────────────────────────────

// Target is a host or service under assessment.
type Target struct {
	ID       string
	Host     string
	Ports    []int
	Services []Service
	Status   TargetStatus
}

// Service describes one service on a target.
type Service struct {
	Port     int
	Protocol string
	Name     string
	Version  string
}

// Finding is a discovered vulnerability or observation.
type Finding struct {
	ID                   string
	MissionID            string
	Title                string
	Description          string
	Severity             Severity
	TargetID             string
	OperatorID           string
	Phase                KillChainPhase
	Evidence             []string
	Remediation          string
	CVSS                 float64
	CVSSVector           string
	ClassificationSource string
	CVE                  []string
	CWE                  string
	CreatedAt            time.Time
}

// Credential represents a discovered credential.
type Credential struct {
	ID             string
	MissionID      string
	Type           string // password, hash, token, apikey, certificate
	Username       string
	Value          string `json:"-"`
	SecretCaptured bool
	Source         string
	TargetID       string
}
