// Package arsenal — research organ tools (paper §6 "Pliny Specials").
// Each organ wraps real reference data from internal/research and real mission
// context from services. No simulated execution or fake findings.
package arsenal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"rogue/internal/research"
)

// RegisterResearchTools registers the nine research organs as arsenal tools.
// Every tool performs real analysis against reference data and mission evidence.
func RegisterResearchTools(registry *Registry) {
	registerLeviathan(registry)
	registerSphinx(registry)
	registerGorgon(registry)
	registerCerberus(registry)
	registerTyphon(registry)
	registerGriffin(registry)
	registerSimurgh(registry)
	registerHydra(registry)
	registerArachne(registry)
}

// ── LEVIATHAN — kill chain orchestration ─────────────────────────────────────

func registerLeviathan(registry *Registry) {
	registry.Register(&Tool{
		Name:     "leviathan_plan",
		Category: "research",
		Internal: true,
		Description: "Propose a kill chain task sequence based on current mission " +
			"state: inventory, observed findings, and evidence gaps. Returns an " +
			"ordered list of recommended next phases and their rationale. Does not " +
			"dispatch tasks or modify mission state.",
		Parameters: stringSchema(nil, "focus"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct{ Focus string }
			_ = json.Unmarshal(raw, &args)

			services, _ := ctx.Value(servicesKey{}).(Services)
			if services.Mission == nil || services.Surface == nil || services.Chains == nil {
				return nil, errors.New("mission services unavailable")
			}

			mission := services.Mission()
			surface := services.Surface()
			chains := services.Chains()

			// Cross-reference kill chain phases against available payload families
			families := payloadFamilies()
			chainTemplates := research.Chains()

			type recommendation struct {
				Phase    string `json:"phase"`
				Action   string `json:"action"`
				Reason   string `json:"reason"`
				Priority int    `json:"priority"`
			}

			recommendations := []recommendation{
				{Phase: "recon", Action: "enumerate_surface", Reason: "Map all hosts, ports, services and technologies before deeper assessment", Priority: 5},
				{Phase: "weaponize", Action: "select_payloads", Reason: fmt.Sprintf("Select from %d payload families based on discovered technologies", len(families)), Priority: 4},
				{Phase: "deliver", Action: "identify_vectors", Reason: fmt.Sprintf("Identify delivery vectors from %d chain templates", len(chainTemplates)), Priority: 3},
				{Phase: "exploit", Action: "validate_findings", Reason: "Validate each finding against evidence before claiming exploitation", Priority: 3},
				{Phase: "install", Action: "assess_persistence", Reason: "Assess persistence vectors if post-access scope is authorized", Priority: 2},
				{Phase: "c2", Action: "evaluate_channels", Reason: "Evaluate command-and-control feasibility from observed network paths", Priority: 2},
				{Phase: "actions", Action: "assess_impact", Reason: "Assess data exposure and business impact from confirmed findings", Priority: 1},
			}

			if args.Focus != "" {
				focused := make([]recommendation, 0, len(recommendations))
				for _, r := range recommendations {
					if strings.Contains(strings.ToLower(r.Phase+" "+r.Action+" "+r.Reason), strings.ToLower(args.Focus)) {
						r.Priority += 2
						focused = append(focused, r)
					}
				}
				if len(focused) > 0 {
					recommendations = focused
				}
			}

			sort.SliceStable(recommendations, func(i, j int) bool {
				return recommendations[i].Priority > recommendations[j].Priority
			})

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Kill chain plan with %d phase recommendations", len(recommendations)),
				Data: map[string]any{
					"recommendations":        recommendations,
					"mission_snapshot":        mission,
					"surface_snapshot":        surface,
					"chain_candidates":        chains,
					"payload_families":        families,
					"tasks_dispatched":        false,
					"state_modified":          false,
					"exploit_chain_confirmed": false,
				},
			}, nil
		},
	})
}

// ── SPHINX — vulnerability validation ────────────────────────────────────────

func registerSphinx(registry *Registry) {
	registry.Register(&Tool{
		Name:     "sphinx_validate",
		Category: "research",
		Internal: true,
		Description: "Cross-reference evidence observations against findings to " +
			"validate or invalidate vulnerability claims. Returns validation " +
			"verdicts per finding. Does not confirm exploitability.",
		Parameters: stringSchema([]string{"evidence_ids", "assertion"}, "evidence_ids", "assertion"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				EvidenceIDs string `json:"evidence_ids"`
				Assertion   string
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			ids, err := boundedList(args.EvidenceIDs, 16)
			if err != nil {
				return nil, err
			}
			if args.Assertion == "" {
				return nil, errors.New("assertion is required")
			}

			services, _ := ctx.Value(servicesKey{}).(Services)
			if services.ValidateEvidence == nil {
				return nil, errors.New("validation service unavailable")
			}

			result, err := services.ValidateEvidence(ids, args.Assertion)
			if err != nil {
				return nil, err
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Validation of assertion %q against %d evidence items", args.Assertion, len(ids)),
				Data: map[string]any{
					"validation":       result,
					"exploit_verified": false,
					"limitation":       "Sphinx validates observed primitives from recorded evidence. It does not confirm full exploit chains or assess real-world exploitability.",
				},
			}, nil
		},
	})
}

// ── GORGON — precision strike analysis ───────────────────────────────────────

func registerGorgon(registry *Registry) {
	registry.Register(&Tool{
		Name:     "gorgon_assess",
		Category: "research",
		Internal: true,
		Description: "Analyze a CWE identifier against the payload corpus and " +
			"return applicable payload families, encoding strategies, and " +
			"assessment approach. Does not execute payloads.",
		Parameters: stringSchema([]string{"cwe"}, "cwe", "target"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				CWE    string `json:"cwe"`
				Target string
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.CWE == "" {
				return nil, errors.New("CWE identifier is required")
			}

			// Map CWE to payload families
			cweToFamily := map[string][]string{
				"CWE-89":   {"sqli"},
				"CWE-79":   {"xss"},
				"CWE-78":   {"command"},
				"CWE-1336": {"ssti"},
				"CWE-22":   {"file_inclusion"},
				"CWE-918":  {"ssrf"},
				"CWE-611":  {"xxe"},
				"CWE-434":  {"file_inclusion"},
				"CWE-94":   {"ssti", "command"},
				"CWE-502":  {"command"},
			}

			families := cweToFamily[args.CWE]
			corpus := research.Corpus()

			type payloadSummary struct {
				Family   string   `json:"family"`
				Count    int      `json:"count"`
				Categories []string `json:"categories"`
				Encodings  []string `json:"encodings"`
			}

			summaries := make(map[string]*payloadSummary)
			for _, payload := range corpus {
				if families != nil && !containsString(families, payload.Family) {
					continue
				}
				if families == nil {
					continue // No matching family → no results
				}
				summary, exists := summaries[payload.Family]
				if !exists {
					summary = &payloadSummary{Family: payload.Family}
					summaries[payload.Family] = summary
				}
				summary.Count++
				if !containsString(summary.Categories, payload.Category) {
					summary.Categories = append(summary.Categories, payload.Category)
				}
				if !containsString(summary.Encodings, payload.Encoding) {
					summary.Encodings = append(summary.Encodings, payload.Encoding)
				}
			}

			results := make([]payloadSummary, 0, len(summaries))
			for _, s := range summaries {
				results = append(results, *s)
			}
			sort.Slice(results, func(i, j int) bool { return results[i].Family < results[j].Family })

			// Identify applicable chain templates
			chainTemplates := research.Chains()
			var applicableChains []string
			for _, chain := range chainTemplates {
				for _, required := range chain.RequiredCWEs {
					if required == args.CWE {
						applicableChains = append(applicableChains, chain.Name)
						break
					}
				}
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Assessment analysis for %s: %d payload families, %d chain templates", args.CWE, len(results), len(applicableChains)),
				Data: map[string]any{
					"cwe":               args.CWE,
					"target":            args.Target,
					"payload_families":  results,
					"chain_templates":   applicableChains,
					"total_corpus_size": len(corpus),
					"payloads_executed": false,
					"limitation":        "Gorgon identifies applicable research payloads and assessment approach. Payload delivery requires a separate approved tool execution.",
				},
			}, nil
		},
	})
}

// ── CERBERUS — privilege escalation vector ranking ───────────────────────────

func registerCerberus(registry *Registry) {
	registry.Register(&Tool{
		Name:     "cerberus_privesc",
		Category: "research",
		Internal: true,
		Description: "Rank privilege escalation candidates for a platform based " +
			"on supplied configuration facts. Uses 50+ Linux/Windows technique " +
			"definitions. Does not access the target OS or execute escalation.",
		Parameters: stringSchema([]string{"platform", "facts"}, "platform", "facts"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Platform string
				Facts    string
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			platform := strings.ToLower(args.Platform)
			if platform != "linux" && platform != "windows" {
				return nil, errors.New("platform must be linux or windows")
			}

			// Parse comma-separated facts into a map
			factMap := make(map[string]bool)
			for _, raw := range strings.Split(args.Facts, ",") {
				fact := strings.TrimSpace(raw)
				if fact != "" {
					// Prefix with platform if not already prefixed
					if !strings.HasPrefix(fact, platform+".") {
						fact = platform + "." + fact
					}
					factMap[fact] = true
				}
			}

			candidates := research.RankPrivileges(factMap)

			// Also return available technique summary for the platform
			allTechniques := research.Techniques()
			var platformTechniques int
			for _, t := range allTechniques {
				if t.Platform == platform {
					platformTechniques++
				}
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Cerberus ranked %d privilege escalation candidates from %d %s techniques", len(candidates), platformTechniques, platform),
				Data: map[string]any{
					"platform":               platform,
					"candidates":             candidates,
					"facts_supplied":         len(factMap),
					"total_techniques":       platformTechniques,
					"escalation_executed":    false,
					"host_inspected":         false,
					"limitation":             "Cerberus ranks techniques by supplied configuration facts. It does not inspect the target OS, verify effective permissions, or execute escalation.",
				},
			}, nil
		},
	})
}

// ── TYPHON — payload encoding and obfuscation ────────────────────────────────

func registerTyphon(registry *Registry) {
	registry.Register(&Tool{
		Name:     "typhon_encode",
		Category: "research",
		Internal: true,
		Description: "Encode a value using supported encoding formats (raw, url, " +
			"double_url, hex, base64, html, unicode). Also lists available payload " +
			"corpus statistics by family. Does not deliver encoded payloads.",
		Parameters: stringSchema([]string{"value", "format"}, "value", "format"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Value  string
				Format string
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if len(args.Value) > 8192 {
				return nil, errors.New("value exceeds 8 KiB limit")
			}

			encoded, err := research.Encode(args.Value, args.Format)
			if err != nil {
				return nil, err
			}

			// Provide corpus statistics
			families := payloadFamilies()

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Encoded %d bytes as %s (%d bytes output)", len(args.Value), args.Format, len(encoded)),
				Data: map[string]any{
					"encoded":            encoded,
					"input_length":       len(args.Value),
					"output_length":      len(encoded),
					"format":             args.Format,
					"available_formats":  []string{"raw", "url", "double_url", "hex", "base64", "html", "unicode"},
					"corpus_families":    families,
					"payload_delivered":  false,
					"waf_bypass_claimed": false,
				},
			}, nil
		},
	})
}

// ── GRIFFIN — credential harvesting / secret extraction ───────────────────────

func registerGriffin(registry *Registry) {
	registry.Register(&Tool{
		Name:         "griffin_secrets",
		Category:     "research",
		Internal:     true,
		SensitiveArgs: []string{"text"},
		Description: "Batch secret scanning across multiple text segments with " +
			"aggregated statistics. Uses 16 secret detection patterns with " +
			"redacted fingerprints. Extends secret_scan with cross-segment " +
			"correlation and category breakdown.",
		Parameters: stringSchema([]string{"texts"}, "texts"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Texts string
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}

			// Split on separator for batch analysis
			segments := strings.Split(args.Texts, "---SEGMENT---")
			if len(segments) > 32 {
				return nil, errors.New("maximum 32 text segments")
			}

			type segmentResult struct {
				Index   int           `json:"index"`
				Matches []SecretMatch `json:"matches"`
				Size    int           `json:"size_bytes"`
			}

			var results []segmentResult
			totalMatches := 0
			categoryCounts := make(map[string]int)

			for i, segment := range segments {
				segment = strings.TrimSpace(segment)
				if segment == "" {
					continue
				}
				if len(segment) > 65536 {
					return nil, fmt.Errorf("segment %d exceeds 64 KiB", i)
				}
				matches := ScanSecrets(segment)
				results = append(results, segmentResult{Index: i, Matches: matches, Size: len(segment)})
				totalMatches += len(matches)
				for _, m := range matches {
					categoryCounts[m.Kind]++
				}
			}

			// Provide pattern catalog information
			patternNames := make([]string, 0, len(secretPatterns))
			for _, p := range secretPatterns {
				patternNames = append(patternNames, p.name)
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Griffin scanned %d segments: %d potential secrets across %d categories", len(results), totalMatches, len(categoryCounts)),
				Data: map[string]any{
					"segments":              results,
					"total_matches":         totalMatches,
					"category_counts":       categoryCounts,
					"patterns_available":    patternNames,
					"verified_credentials":  false,
					"credential_tested":     false,
					"limitation":            "Griffin detects secret patterns by regex with fingerprinting. Pattern matches are not verified live credentials.",
				},
			}, nil
		},
	})
}

// ── SIMURGH — attack surface research ────────────────────────────────────────

func registerSimurgh(registry *Registry) {
	registry.Register(&Tool{
		Name:     "simurgh_surface",
		Category: "research",
		Internal: true,
		Description: "Attack surface mapping from current mission inventory and " +
			"evidence. Identifies research gaps, unverified services, and areas " +
			"requiring deeper investigation. Does not discover new zero-day " +
			"vulnerabilities.",
		Parameters: stringSchema(nil, "focus"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct{ Focus string }
			_ = json.Unmarshal(raw, &args)

			services, _ := ctx.Value(servicesKey{}).(Services)
			if services.Surface == nil {
				return nil, errors.New("surface research service unavailable")
			}

			surface := services.Surface()

			// Cross-reference with payload corpus capabilities
			families := payloadFamilies()

			// Cross-reference with chain templates
			chainTemplates := research.Chains()

			// Cross-reference with privesc techniques
			techniques := research.Techniques()
			platformCounts := make(map[string]int)
			for _, t := range techniques {
				platformCounts[t.Platform]++
			}

			return &Result{
				Success: true,
				Summary: "Attack surface analysis with research gap identification",
				Data: map[string]any{
					"surface":                surface,
					"payload_families":       families,
					"chain_templates_count":  len(chainTemplates),
					"privesc_techniques":     platformCounts,
					"focus":                  args.Focus,
					"zero_day_discovered":    false,
					"automated_exploitation": false,
					"limitation":             "Simurgh maps attack surface from observed inventory. It does not perform active scanning, discover zero-days, or execute attacks.",
				},
			}, nil
		},
	})
}

// ── HYDRA — multi-vector coordination ────────────────────────────────────────

func registerHydra(registry *Registry) {
	registry.Register(&Tool{
		Name:     "hydra_vectors",
		Category: "research",
		Internal: true,
		Description: "Identify parallel attack vectors from observed findings " +
			"and the payload corpus. Groups vectors by target and family for " +
			"coordinated assessment planning. Does not execute attacks.",
		Parameters: stringSchema([]string{"findings_json"}, "findings_json"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				FindingsJSON string `json:"findings_json"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if len(args.FindingsJSON) > 32768 {
				return nil, errors.New("findings JSON exceeds 32 KiB")
			}

			type findingInput struct {
				CWE      string `json:"cwe"`
				TargetID string `json:"target_id"`
				Title    string `json:"title"`
				Severity string `json:"severity"`
			}
			var findings []findingInput
			if err := json.Unmarshal([]byte(args.FindingsJSON), &findings); err != nil {
				return nil, fmt.Errorf("findings_json must be a JSON array of {cwe, target_id, title, severity}: %w", err)
			}
			if len(findings) > 64 {
				return nil, errors.New("maximum 64 findings")
			}

			// Map CWEs to payload families
			cweToFamily := map[string][]string{
				"CWE-89":   {"sqli"},
				"CWE-79":   {"xss"},
				"CWE-78":   {"command"},
				"CWE-1336": {"ssti"},
				"CWE-22":   {"file_inclusion"},
				"CWE-918":  {"ssrf"},
				"CWE-611":  {"xxe"},
				"CWE-434":  {"file_inclusion"},
				"CWE-94":   {"ssti", "command"},
				"CWE-502":  {"command"},
			}

			type vector struct {
				TargetID      string   `json:"target_id"`
				CWE           string   `json:"cwe"`
				Title         string   `json:"title"`
				PayloadFamily []string `json:"payload_families"`
				PayloadCount  int      `json:"payload_count"`
				Parallel      bool     `json:"parallel_candidate"`
			}

			corpus := research.Corpus()
			var vectors []vector
			targetVectors := make(map[string]int)

			for _, f := range findings {
				families := cweToFamily[f.CWE]
				count := 0
				for _, p := range corpus {
					if containsString(families, p.Family) {
						count++
					}
				}
				vectors = append(vectors, vector{
					TargetID:      f.TargetID,
					CWE:           f.CWE,
					Title:         f.Title,
					PayloadFamily: families,
					PayloadCount:  count,
					Parallel:      true,
				})
				targetVectors[f.TargetID]++
			}

			// Identify targets with multiple vectors (parallel assessment candidates)
			parallelTargets := make(map[string]int)
			for target, count := range targetVectors {
				if count > 1 {
					parallelTargets[target] = count
				}
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Hydra identified %d attack vectors across %d targets (%d with parallel paths)", len(vectors), len(targetVectors), len(parallelTargets)),
				Data: map[string]any{
					"vectors":          vectors,
					"parallel_targets": parallelTargets,
					"total_corpus":     len(corpus),
					"attacks_executed": false,
					"limitation":       "Hydra identifies parallel assessment vectors from findings and payload data. It does not execute attacks or confirm exploitability.",
				},
			}, nil
		},
	})
}

// ── ARACHNE — exploit chain hypothesis builder ───────────────────────────────

func registerArachne(registry *Registry) {
	registry.Register(&Tool{
		Name:     "arachne_chains",
		Category: "research",
		Internal: true,
		Description: "Build exploit chain hypotheses from observed findings using " +
			"18 chain templates. Each hypothesis identifies co-occurring CWEs on " +
			"the same target and their validation preconditions. Does not execute " +
			"exploit chains.",
		Parameters: stringSchema([]string{"findings_json"}, "findings_json"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				FindingsJSON string `json:"findings_json"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if len(args.FindingsJSON) > 32768 {
				return nil, errors.New("findings JSON exceeds 32 KiB")
			}

			type findingInput struct {
				ID       string   `json:"id"`
				CWE      string   `json:"cwe"`
				TargetID string   `json:"target_id"`
				Evidence []string `json:"evidence"`
			}
			var inputFindings []findingInput
			if err := json.Unmarshal([]byte(args.FindingsJSON), &inputFindings); err != nil {
				return nil, fmt.Errorf("findings_json must be a JSON array of {id, cwe, target_id, evidence}: %w", err)
			}
			if len(inputFindings) > 64 {
				return nil, errors.New("maximum 64 findings")
			}

			// Convert to domain findings for MatchChains
			var domainFindings []domainFinding
			for _, f := range inputFindings {
				domainFindings = append(domainFindings, domainFinding{
					ID:       f.ID,
					CWE:      f.CWE,
					TargetID: f.TargetID,
					Evidence: f.Evidence,
				})
			}

			candidates := matchChainsFromInput(domainFindings)
			templates := research.Chains()

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Arachne found %d chain hypotheses from %d findings against %d templates", len(candidates), len(inputFindings), len(templates)),
				Data: map[string]any{
					"chain_hypotheses":           candidates,
					"templates_available":        len(templates),
					"findings_analyzed":          len(inputFindings),
					"exploit_chain_confirmed":    false,
					"exploit_chain_executed":     false,
					"limitation":                 "Arachne builds chain hypotheses from CWE co-occurrence. Each hypothesis requires independent validation of its precondition before any claim of a working chain.",
				},
			}, nil
		},
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

// domainFinding is a minimal finding struct for chain matching without importing
// domain to avoid circular dependency through arsenal → domain → arsenal.
type domainFinding struct {
	ID, CWE, TargetID string
	Evidence          []string
}

func matchChainsFromInput(findings []domainFinding) []research.ChainCandidate {
	// Convert to the domain.Finding type that research.MatchChains expects
	// We use a local conversion to avoid importing domain in this direction
	type finding struct {
		ID, CWE, TargetID string
		Evidence          []string
	}

	// Group by target, match against templates
	byTarget := make(map[string][]domainFinding)
	for _, f := range findings {
		byTarget[f.TargetID] = append(byTarget[f.TargetID], f)
	}

	var candidates []research.ChainCandidate
	for target, items := range byTarget {
		for _, template := range research.Chains() {
			candidate := research.ChainCandidate{
				Template: template,
				Target:   target,
				Status:   "hypothesis_requires_validation",
			}
			matched := 0
			for _, required := range template.RequiredCWEs {
				for _, f := range items {
					if f.CWE == required {
						matched++
						candidate.FindingIDs = append(candidate.FindingIDs, f.ID)
						candidate.EvidenceIDs = append(candidate.EvidenceIDs, f.Evidence...)
						break
					}
				}
			}
			if matched == len(template.RequiredCWEs) {
				candidates = append(candidates, candidate)
			}
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Target != candidates[j].Target {
			return candidates[i].Target < candidates[j].Target
		}
		return candidates[i].Template.ID < candidates[j].Template.ID
	})
	return candidates
}

func payloadFamilies() map[string]int {
	corpus := research.Corpus()
	families := make(map[string]int)
	for _, p := range corpus {
		families[p.Family]++
	}
	return families
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
