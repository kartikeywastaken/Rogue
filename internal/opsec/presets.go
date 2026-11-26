package opsec

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Profile configures timing, detection thresholds, and traffic blending for a
// mission. Lower-noise profiles introduce randomized request jitter and rotate
// HTTP fingerprint headers.
type Profile struct {
	Name         string
	JitterMin    time.Duration
	JitterMax    time.Duration
	BlendTraffic bool
	PauseAfter   int
	AbortAfter   int
	Cooldown     time.Duration
}

// Policy converts an OPSEC profile into an opsec.Policy threshold pair.
func (p Profile) Policy() Policy {
	return Policy{PauseAfter: p.PauseAfter, AbortAfter: p.AbortAfter}
}

// RoEPreset bundles authorization strictness and OPSEC posture into a named
// Rules-of-Engagement configuration.
type RoEPreset struct {
	Name            string
	Description     string
	Mode            string // "default" or "auto"
	RequireApproval bool
	AllowLab        bool
	OPSEC           Profile
}

var (
	// Silent — maximum evasion: heavy jitter, blended headers, tight pause/abort.
	Silent = Profile{
		Name:         "silent",
		JitterMin:    2 * time.Second,
		JitterMax:    8 * time.Second,
		BlendTraffic: true,
		PauseAfter:   2,
		AbortAfter:   4,
		Cooldown:     15 * time.Second,
	}
	// Covert — moderate evasion: light jitter, blended headers, balanced thresholds.
	Covert = Profile{
		Name:         "covert",
		JitterMin:    500 * time.Millisecond,
		JitterMax:    2 * time.Second,
		BlendTraffic: true,
		PauseAfter:   5,
		AbortAfter:   10,
		Cooldown:     5 * time.Second,
	}
	// Loud — no artificial jitter: full throughput for lab/benchmark suites.
	Loud = Profile{
		Name:         "loud",
		JitterMin:    0,
		JitterMax:    0,
		BlendTraffic: false,
		PauseAfter:   0,
		AbortAfter:   0,
		Cooldown:     0,
	}

	// StrictRoE enforces per-action operator approval, conservative silent OPSEC,
	// and disables unattended auto-execution.
	StrictRoE = RoEPreset{
		Name:            "strict",
		Description:     "Strict Rules of Engagement: default approval mode, silent OPSEC thresholds, no unattended active probes",
		Mode:            "default",
		RequireApproval: true,
		AllowLab:        false,
		OPSEC:           Silent,
	}

	// DefaultRoE uses scoped auto mode with covert OPSEC jitter within ROGUE_SCOPE.
	DefaultRoE = RoEPreset{
		Name:            "default",
		Description:     "Default Rules of Engagement: scoped assessment within ROGUE_SCOPE with covert timing and gated lab actions",
		Mode:            "auto",
		RequireApproval: false,
		AllowLab:        false,
		OPSEC:           Covert,
	}
)

var (
	profileMu     sync.RWMutex
	activeProfile = Loud
	activeRoE     = DefaultRoE
)

// Profiles returns all named OPSEC profiles.
func Profiles() []Profile {
	return []Profile{Silent, Covert, Loud}
}

// RoEPresets returns all named Rules-of-Engagement presets.
func RoEPresets() []RoEPreset {
	return []RoEPreset{StrictRoE, DefaultRoE}
}

// LookupProfile returns a named OPSEC profile ("silent", "covert", "loud").
func LookupProfile(name string) (Profile, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "silent":
		return Silent, true
	case "covert":
		return Covert, true
	case "loud":
		return Loud, true
	default:
		return Profile{}, false
	}
}

// LookupRoE returns a named RoE preset ("strict", "default").
func LookupRoE(name string) (RoEPreset, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "strict", "strict_roe":
		return StrictRoE, true
	case "default", "default_roe":
		return DefaultRoE, true
	default:
		return RoEPreset{}, false
	}
}

// ActiveProfileSnapshot returns the currently active OPSEC profile safely.
func ActiveProfileSnapshot() Profile {
	profileMu.RLock()
	defer profileMu.RUnlock()
	return activeProfile
}

// SetProfile switches the active OPSEC profile by name ("silent", "covert", "loud").
// Unknown names are ignored and return false.
func SetProfile(name string) bool {
	p, ok := LookupProfile(name)
	if !ok {
		return false
	}
	profileMu.Lock()
	activeProfile = p
	profileMu.Unlock()
	return true
}

// ActiveRoESnapshot returns the active Rules-of-Engagement preset safely.
func ActiveRoESnapshot() RoEPreset {
	profileMu.RLock()
	defer profileMu.RUnlock()
	return activeRoE
}

// SetRoE switches the active RoE preset and synchronizes the OPSEC profile.
func SetRoE(name string) bool {
	roe, ok := LookupRoE(name)
	if !ok {
		return false
	}
	profileMu.Lock()
	activeRoE = roe
	activeProfile = roe.OPSEC
	profileMu.Unlock()
	return true
}

func secureRandInt64(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

// JitterDelay returns a random duration in [JitterMin, JitterMax] for the
// active profile.
func JitterDelay(ctx context.Context) time.Duration {
	if ctx.Err() != nil {
		return 0
	}
	p := ActiveProfileSnapshot()
	if p.JitterMax <= 0 {
		return 0
	}
	if p.JitterMax <= p.JitterMin {
		return p.JitterMin
	}
	spread := int64(p.JitterMax - p.JitterMin)
	return p.JitterMin + time.Duration(secureRandInt64(spread))
}

// Sleep blocks for JitterDelay, returning early if ctx is cancelled.
func Sleep(ctx context.Context) error {
	d := JitterDelay(ctx)
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var userAgentPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
}

var acceptLanguagePool = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9,en-US;q=0.8",
	"en-US,en;q=0.8",
}

// RandomUserAgent returns a randomized browser User-Agent when traffic blending
// is active, or ROGUE's standard identifier otherwise.
func RandomUserAgent() string {
	p := ActiveProfileSnapshot()
	if !p.BlendTraffic {
		return "ROGUE-Research/1.0"
	}
	return userAgentPool[secureRandInt64(int64(len(userAgentPool)))]
}

// ApplyBlendHeaders sets randomized User-Agent and browser-like Accept headers
// on req when BlendTraffic is active.
func ApplyBlendHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Set("User-Agent", RandomUserAgent())
	p := ActiveProfileSnapshot()
	if p.BlendTraffic {
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		}
		if req.Header.Get("Accept-Language") == "" {
			req.Header.Set("Accept-Language", acceptLanguagePool[secureRandInt64(int64(len(acceptLanguagePool)))])
		}
	}
}
