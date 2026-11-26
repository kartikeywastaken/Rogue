package opsec

import (
	"context"
	"math/rand"
	"time"
)

// Profile configures timing and blend behaviour for a mission.
// Lower-numbered profiles introduce jitter and blend traffic to reduce
// the probability of detection by WAFs and IDS signatures.
type Profile struct {
	Name        string
	JitterMin   time.Duration
	JitterMax   time.Duration
	BlendTraffic bool // rotate User-Agent per request
}

var (
	// Silent — maximum evasion: heavy jitter, blended user-agents.
	Silent = Profile{
		Name:         "silent",
		JitterMin:    2 * time.Second,
		JitterMax:    8 * time.Second,
		BlendTraffic: true,
	}
	// Covert — moderate evasion: light jitter, blended user-agents.
	Covert = Profile{
		Name:         "covert",
		JitterMin:    500 * time.Millisecond,
		JitterMax:    2 * time.Second,
		BlendTraffic: true,
	}
	// Loud — no evasion: speed over stealth (default for lab/bench runs).
	Loud = Profile{
		Name:         "loud",
		JitterMin:    0,
		JitterMax:    0,
		BlendTraffic: false,
	}
)

// ActiveProfile holds the globally active OPSEC profile.
// Default is Loud (permissive) so lab runs are unaffected.
var ActiveProfile = Loud

// SetProfile switches the active profile by name ("silent", "covert", "loud").
// Unknown names are silently ignored (keeps previous profile).
func SetProfile(name string) {
	switch name {
	case "silent":
		ActiveProfile = Silent
	case "covert":
		ActiveProfile = Covert
	case "loud":
		ActiveProfile = Loud
	}
}

// JitterDelay returns a random duration in [JitterMin, JitterMax] for the
// active profile. It respects context cancellation so long sleeps abort cleanly.
func JitterDelay(ctx context.Context) time.Duration {
	p := ActiveProfile
	if p.JitterMax <= p.JitterMin {
		return 0
	}
	spread := p.JitterMax - p.JitterMin
	jitter := p.JitterMin + time.Duration(rand.Int63n(int64(spread)))
	return jitter
}

// Sleep blocks for JitterDelay, returning early on context cancellation.
func Sleep(ctx context.Context) error {
	d := JitterDelay(ctx)
	if d <= 0 {
		return ctx.Err()
	}
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// userAgentPool is a small set of realistic browser UAs for traffic blending.
var userAgentPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
}

// RandomUserAgent returns a randomly selected real browser user-agent string.
// Falls back to a neutral string when blending is disabled.
func RandomUserAgent() string {
	if !ActiveProfile.BlendTraffic {
		return "ROGUE-Research/1.0"
	}
	return userAgentPool[rand.Intn(len(userAgentPool))]
}
