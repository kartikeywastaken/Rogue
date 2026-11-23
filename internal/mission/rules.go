package mission

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Rules are explicit authorization, never inferred from model-generated text.
// Scope entries are exact hostnames, IPs, or CIDRs; exclusions take precedence.
type Rules struct {
	Scope            []string
	Excluded         []string
	AllowedTools     []string
	PreapprovedTools []string
}

func (r Rules) clone() Rules {
	r.Scope = slices.Clone(r.Scope)
	r.Excluded = slices.Clone(r.Excluded)
	r.AllowedTools = slices.Clone(r.AllowedTools)
	r.PreapprovedTools = slices.Clone(r.PreapprovedTools)
	return r
}
func canonical(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func (r Rules) Validate() error {
	for _, set := range [][]string{r.Scope, r.Excluded} {
		for _, s := range set {
			if _, err := netip.ParsePrefix(s); err == nil {
				continue
			}
			if _, err := netip.ParseAddr(s); err == nil {
				continue
			}
			if canonical(s) == "" || strings.ContainsAny(s, "/:*?@ \\#\t\r\n") {
				return fmt.Errorf("invalid scope entry %q: use exact host, IP, or CIDR", s)
			}
		}
	}
	for _, t := range r.PreapprovedTools {
		if len(r.AllowedTools) > 0 && !slices.Contains(r.AllowedTools, t) {
			return fmt.Errorf("preapproved tool %q is not allowed", t)
		}
	}
	return nil
}
func matches(entries []string, host string) bool {
	host = canonical(strings.Trim(host, "[]"))
	ip, ipErr := netip.ParseAddr(host)
	for _, entry := range entries {
		if p, err := netip.ParsePrefix(entry); err == nil {
			if ipErr == nil && p.Contains(ip.Unmap()) {
				return true
			}
			continue
		}
		if e, err := netip.ParseAddr(entry); err == nil {
			if ipErr == nil && e.Unmap() == ip.Unmap() {
				return true
			}
			continue
		}
		if canonical(entry) == host {
			return true
		}
	}
	return false
}
func (r Rules) AllowsHost(host string) bool {
	return !matches(r.Excluded, host) && matches(r.Scope, host)
}

// AllowsAddress checks the actual socket peer as well as the authorized hostname.
// A scoped DNS name authorizes its resolved addresses except explicit exclusions.
func (r Rules) AllowsAddress(host, address string) bool {
	return !matches(r.Excluded, host) && !matches(r.Excluded, address) && (matches(r.Scope, host) || matches(r.Scope, address))
}
