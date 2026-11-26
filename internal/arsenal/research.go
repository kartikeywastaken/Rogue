// Package arsenal — research organ tools (paper §6 "Pliny Specials").
// Each organ wraps real reference data from internal/research and real mission
// context from services. When execute=true, the organ acts on its own
// recommendations using bounded HTTP probes or safe read-only OS checks.
// No simulated execution or fake findings are ever returned.
package arsenal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"rogue/internal/opsec"
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

// cwePayloadFamilies maps CWE identifiers to payload corpus families.
// Used by GORGON and HYDRA to map findings to actionable payload candidates.
var cwePayloadFamilies = map[string][]string{
	// Injection
	"CWE-89":   {"sqli"},
	"CWE-79":   {"xss"},
	"CWE-78":   {"command"},
	"CWE-77":   {"command"},
	"CWE-74":   {"sqli", "xss", "command"},
	"CWE-1336": {"ssti"},
	"CWE-94":   {"ssti", "command"},
	"CWE-502":  {"command"},
	// Path traversal and file inclusion
	"CWE-22":   {"file_inclusion"},
	"CWE-23":   {"file_inclusion"},
	"CWE-434":  {"file_inclusion"},
	// SSRF
	"CWE-918":  {"ssrf"},
	// XXE
	"CWE-611":  {"xxe"},
	"CWE-776":  {"xxe"},
	// Open redirect — no dedicated family but ssrf covers server-side redirects
	"CWE-601":  {"ssrf"},
	// Auth — no direct payload family; use sqli for bypass attempts
	"CWE-287":  {"sqli"},
	"CWE-306":  {"sqli"},
	"CWE-307":  {"sqli"},
	// XSS-related
	"CWE-352":  {"xss"},
	"CWE-116":  {"xss"},
	// Access control — use all injection families for probing
	"CWE-862":  {"sqli", "xss"},
	"CWE-863":  {"sqli", "xss"},
	"CWE-639":  {"sqli"},
	"CWE-284":  {"sqli", "ssrf"},
	// Deserialization / type confusion
	"CWE-915":  {"command", "ssti"},
}

// researchSchema builds a JSON Schema where execute (and optional boolFields) are
// typed boolean so Registry.Exec validates execute=true properly alongside string fields.
func researchSchema(required []string, boolFields []string, fields ...string) map[string]any {
	schema := stringSchema(required, fields...)
	props := schema["properties"].(map[string]any)
	for _, bf := range boolFields {
		props[bf] = map[string]any{"type": "boolean"}
	}
	return schema
}

// probeGET makes a bounded GET to rawURL using the policy-scoped client (DNS-rebinding
// protection + redirect target scope enforcement) and OPSEC jitter. Up to 64 KB body.
func probeGET(ctx context.Context, rawURL string) (status int, body string, err error) {
	if err := opsec.Sleep(ctx); err != nil {
		return 0, "", err
	}
	if _, scopeErr := checkURL(ctx, rawURL); scopeErr != nil {
		return 0, "", fmt.Errorf("probe out of scope: %w", scopeErr)
	}
	client := newScopedHTTPClient(3, true)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", err
	}
	opsec.ApplyBlendHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return resp.StatusCode, string(b), nil
}

// probePOST makes a bounded POST to rawURL with form values or a JSON body using
// the policy-scoped client and OPSEC jitter. bodyType is "form" or "json".
func probePOST(ctx context.Context, rawURL, bodyType, payload string) (status int, body string, err error) {
	if err := opsec.Sleep(ctx); err != nil {
		return 0, "", err
	}
	if _, scopeErr := checkURL(ctx, rawURL); scopeErr != nil {
		return 0, "", fmt.Errorf("probe out of scope: %w", scopeErr)
	}
	var (
		contentType string
		bodyData    string
	)
	switch bodyType {
	case "json":
		contentType = "application/json"
		bodyData = payload
	default: // "form"
		contentType = "application/x-www-form-urlencoded"
		bodyData = payload
	}
	client := newScopedHTTPClient(3, true)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(bodyData))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", contentType)
	opsec.ApplyBlendHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return resp.StatusCode, string(b), nil
}

// analyzeResponse checks a response body for common indicators of injection
// success. It never confirms exploitation — only records primitive observations.
func analyzeResponse(body, payload string) map[string]any {
	lower := strings.ToLower(body)
	analysis := map[string]any{
		"response_bytes":   len(body),
		"payload_reflected": strings.Contains(body, payload),
	}
	// SQL error indicators
	sqlErrors := []string{
		"sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite_",
		"unclosed quotation", "quoted string not properly terminated",
		"syntax error", "you have an error in your sql",
	}
	for _, indicator := range sqlErrors {
		if strings.Contains(lower, indicator) {
			analysis["sql_error_indicator"] = true
			break
		}
	}
	// XSS reflection
	if strings.Contains(body, "<script") || strings.Contains(body, "onerror=") || strings.Contains(body, "onload=") {
		analysis["script_tag_present"] = true
	}
	// Path traversal indicators
	if strings.Contains(body, "root:x:") || strings.Contains(body, "[boot loader]") || strings.Contains(body, "proc/version") {
		analysis["path_traversal_indicator"] = true
	}
	// SSTI indicators (arithmetic evaluation)
	if strings.Contains(body, "49") && strings.Contains(payload, "7*7") {
		analysis["ssti_arithmetic_indicator"] = true
	}
	// Server error
	analysis["server_error"] = strings.Contains(lower, "internal server error") ||
		strings.Contains(lower, "exception") || strings.Contains(lower, "stack trace")
	return analysis
}

// injectURL substitutes ROGUE_INJECT in rawURL with value, or appends value
// as query parameter "q" if no placeholder is present.
func injectURL(rawURL, value string) string {
	if strings.Contains(rawURL, "ROGUE_INJECT") {
		return strings.ReplaceAll(rawURL, "ROGUE_INJECT", url.QueryEscape(value))
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("q", value)
	u.RawQuery = q.Encode()
	return u.String()
}

// injectPostBody builds a URL-encoded form body substituting ROGUE_INJECT with
// the value, or returning a default field=value form body.
func injectPostBody(template, fieldName, value string) string {
	if strings.Contains(template, "ROGUE_INJECT") {
		return strings.ReplaceAll(template, "ROGUE_INJECT", url.QueryEscape(value))
	}
	if fieldName == "" {
		fieldName = "q"
	}
	return fieldName + "=" + url.QueryEscape(value)
}

// ── LEVIATHAN — kill chain orchestration ─────────────────────────────────────

func registerLeviathan(registry *Registry) {
	registry.Register(&Tool{
		Name:     "leviathan_plan",
		Category: "research",
		Internal: true,
		Description: "Propose a kill chain task sequence based on current mission " +
			"state: inventory, observed findings, and evidence gaps. Returns an " +
			"ordered list of recommended next phases and their rationale. When " +
			"execute=true, dispatches the top-3 priority phases as task proposals " +
			"via mission control (requires supervisor service). Does not modify " +
			"state autonomously beyond the proposal API.",
		Parameters: researchSchema(nil, []string{"execute"}, "focus", "execute"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Focus   string
				Execute bool
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Execute {
				if err := authorizeActive(ctx, "leviathan_plan", raw); err != nil {
					return nil, err
				}
			}

			services, _ := ctx.Value(servicesKey{}).(Services)
			if services.Mission == nil || services.Surface == nil || services.Chains == nil {
				return nil, errors.New("mission services unavailable")
			}

			mission := services.Mission()
			surface := services.Surface()
			chains := services.Chains()
			families := payloadFamilies()
			chainTemplates := research.Chains()

			type recommendation struct {
				Phase    string `json:"phase"`
				Action   string `json:"action"`
				Role     string `json:"role"`
				Reason   string `json:"reason"`
				Priority int    `json:"priority"`
			}

			recommendations := []recommendation{
				{Phase: "recon", Action: "enumerate_surface", Role: "recon", Reason: "Map all hosts, ports, services and technologies before deeper assessment", Priority: 5},
				{Phase: "weaponize", Action: "select_payloads", Role: "analyst", Reason: fmt.Sprintf("Select from %d payload families based on discovered technologies", len(families)), Priority: 4},
				{Phase: "deliver", Action: "identify_vectors", Role: "scanner", Reason: fmt.Sprintf("Identify delivery vectors from %d chain templates", len(chainTemplates)), Priority: 3},
				{Phase: "exploit", Action: "validate_findings", Role: "exploiter", Reason: "Validate each finding against evidence before claiming exploitation", Priority: 3},
				{Phase: "install", Action: "assess_persistence", Role: "infiltrator", Reason: "Assess persistence vectors if post-access scope is authorized", Priority: 2},
				{Phase: "c2", Action: "evaluate_channels", Role: "infiltrator", Reason: "Evaluate command-and-control feasibility from observed network paths", Priority: 2},
				{Phase: "actions", Action: "assess_impact", Role: "exfiltrator", Reason: "Assess data exposure and business impact from confirmed findings", Priority: 1},
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

			data := map[string]any{
				"recommendations":         recommendations,
				"mission_snapshot":        mission,
				"surface_snapshot":        surface,
				"chain_candidates":        chains,
				"payload_families":        families,
				"tasks_dispatched":        false,
				"state_modified":          false,
				"exploit_chain_confirmed": false,
			}

			if args.Execute {
				if services.Propose == nil {
					return nil, errors.New("execute=true requires supervisor service (propose); not available in this context")
				}
				type dispatchResult struct {
					Phase  string `json:"phase"`
					Role   string `json:"role"`
					Action string `json:"action"`
					Result any    `json:"result,omitempty"`
					Error  string `json:"error,omitempty"`
				}

				// Gather available evidence IDs — proposals require 1-8 supporting observations.
				var evidenceIDs []string
				if services.Evidence != nil {
					rawEvidence, _ := services.Evidence(nil)
					if evMap, ok := rawEvidence.(map[string]any); ok {
						if obs, ok := evMap["observations"].([]any); ok {
							for _, o := range obs {
								if om, ok := o.(map[string]any); ok {
									if id, ok := om["id"].(string); ok && id != "" {
										evidenceIDs = append(evidenceIDs, id)
										if len(evidenceIDs) >= 4 {
											break
										}
									}
								}
							}
						}
					}
				}
				if len(evidenceIDs) == 0 {
					data["tasks_dispatched"] = false
					data["dispatch_note"] = "No recorded observations available to support task proposals; run recon tools first to build evidence."
				} else {
					var dispatched []dispatchResult
					limit := 3
					if len(recommendations) < limit {
						limit = len(recommendations)
					}
					// Provide up to 2 evidence IDs per proposal (minimum 1 required).
					propEvidence := evidenceIDs
					if len(propEvidence) > 2 {
						propEvidence = propEvidence[:2]
					}
					for _, rec := range recommendations[:limit] {
						proposal := TaskProposal{
							Title:       fmt.Sprintf("%s: %s", rec.Phase, rec.Action),
							Role:        rec.Role,
							EvidenceIDs: propEvidence,
						}
						result, err := services.Propose(proposal)
						dr := dispatchResult{Phase: rec.Phase, Role: rec.Role, Action: rec.Action, Result: result}
						if err != nil {
							dr.Error = err.Error()
						}
						dispatched = append(dispatched, dr)
					}
					data["tasks_dispatched"] = true
					data["dispatch_results"] = dispatched
				}
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Kill chain plan with %d phase recommendations", len(recommendations)),
				Data:    data,
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
			"verdicts per finding. When execute=true and target_url is set, " +
			"performs a live HTTP GET to the target and reports whether the " +
			"assertion indicator appears in the response body. Does not confirm " +
			"exploitability.",
		Parameters: researchSchema([]string{"evidence_ids", "assertion"}, []string{"execute"}, "evidence_ids", "assertion", "target_url", "execute"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				EvidenceIDs string `json:"evidence_ids"`
				Assertion   string
				TargetURL   string `json:"target_url"`
				Execute     bool
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Execute {
				if err := authorizeActive(ctx, "sphinx_validate", raw); err != nil {
					return nil, err
				}
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

			data := map[string]any{
				"validation":       result,
				"exploit_verified": false,
				"limitation":       "Sphinx validates observed primitives from recorded evidence. It does not confirm full exploit chains or assess real-world exploitability.",
			}

			if args.Execute && args.TargetURL != "" {
				status, body, probeErr := probeGET(ctx, args.TargetURL)
				probeData := map[string]any{
					"url":             args.TargetURL,
					"status":          status,
					"response_bytes":  len(body),
					"assertion_found": strings.Contains(body, args.Assertion),
				}
				if probeErr != nil {
					probeData["error"] = probeErr.Error()
				}
				data["live_probe"] = probeData
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Validation of assertion %q against %d evidence items", args.Assertion, len(ids)),
				Data:    data,
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
			"assessment approach. When execute=true and target is a URL, delivers " +
			"up to 8 raw payload candidates via HTTP GET probes. Use ROGUE_INJECT " +
			"in the target URL as the injection point, or the value is appended " +
			"as query param 'q'.",
		Parameters: researchSchema([]string{"cwe"}, []string{"execute"}, "cwe", "target", "execute"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				CWE     string `json:"cwe"`
				Target  string
				Execute bool
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Execute {
				if err := authorizeActive(ctx, "gorgon_assess", raw); err != nil {
					return nil, err
				}
			}
			if args.CWE == "" {
				return nil, errors.New("CWE identifier is required")
			}

			cweToFamily := cwePayloadFamilies

			families := cweToFamily[args.CWE]
			corpus := research.Corpus()

			type payloadSummary struct {
				Family     string   `json:"family"`
				Count      int      `json:"count"`
				Categories []string `json:"categories"`
				Encodings  []string `json:"encodings"`
			}

			summaries := make(map[string]*payloadSummary)
			var rawPayloads []research.Payload
			for _, payload := range corpus {
				if families != nil && !containsString(families, payload.Family) {
					continue
				}
				if families == nil {
					continue
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
				if payload.Encoding == "raw" {
					rawPayloads = append(rawPayloads, payload)
				}
			}

			results := make([]payloadSummary, 0, len(summaries))
			for _, s := range summaries {
				results = append(results, *s)
			}
			sort.Slice(results, func(i, j int) bool { return results[i].Family < results[j].Family })

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

			data := map[string]any{
				"cwe":               args.CWE,
				"target":            args.Target,
				"payload_families":  results,
				"chain_templates":   applicableChains,
				"total_corpus_size": len(corpus),
				"payloads_executed": false,
				"limitation":        "Gorgon identifies applicable research payloads. When execute=true, delivers up to 8 raw payloads via GET and POST to the target URL and reports observed indicators (reflected content, SQL errors, server errors). Does not confirm exploitability.",
			}

			if args.Execute && args.Target != "" {
				limit := 8
				if len(rawPayloads) < limit {
					limit = len(rawPayloads)
				}
				type probeResult struct {
					Payload   string         `json:"payload"`
					Family    string         `json:"family"`
					Category  string         `json:"category"`
					GetStatus int            `json:"get_status,omitempty"`
					PostStatus int           `json:"post_status,omitempty"`
					Analysis  map[string]any `json:"analysis,omitempty"`
					Error     string         `json:"error,omitempty"`
				}
				probes := make([]probeResult, 0, limit)
				for _, p := range rawPayloads[:limit] {
					pr := probeResult{Payload: p.Value, Family: p.Family, Category: p.Category}
					targetURL := injectURL(args.Target, p.Value)
					getStatus, getBody, getErr := probeGET(ctx, targetURL)
					if getErr != nil {
						pr.Error = getErr.Error()
					} else {
						pr.GetStatus = getStatus
						pr.Analysis = analyzeResponse(getBody, p.Value)
					}
					// Also try POST with form body for injection families
					if p.Family == "sqli" || p.Family == "xss" || p.Family == "ssti" || p.Family == "command" {
						postBody := injectPostBody("", "", p.Value)
						postStatus, postBody2, postErr := probePOST(ctx, args.Target, "form", postBody)
						if postErr == nil {
							pr.PostStatus = postStatus
							postAnalysis := analyzeResponse(postBody2, p.Value)
							for k, v := range postAnalysis {
								pr.Analysis["post_"+k] = v
							}
						}
					}
					probes = append(probes, pr)
				}
				data["payloads_executed"] = true
				data["probe_results"] = probes
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Assessment analysis for %s: %d payload families, %d chain templates", args.CWE, len(results), len(applicableChains)),
				Data:    data,
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
			"definitions. When execute=true, runs safe read-only OS checks locally or " +
			"over SSH (when ssh_target is set and in scope) to gather live facts before " +
			"ranking. Does not execute privilege escalation.",
		Parameters: researchSchema([]string{"platform", "facts"}, []string{"execute"},
			"platform", "facts", "execute", "ssh_target", "ssh_user", "ssh_port", "credential_id"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Platform     string
				Facts        string
				Execute      bool
				SSHTarget    string `json:"ssh_target"`
				SSHUser      string `json:"ssh_user"`
				SSHPort      string `json:"ssh_port"`
				CredentialID string `json:"credential_id"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Execute {
				if err := authorizeActive(ctx, "cerberus_privesc", raw); err != nil {
					return nil, err
				}
			}
			platform := strings.ToLower(args.Platform)
			if platform != "linux" && platform != "windows" {
				return nil, errors.New("platform must be linux or windows")
			}

			factMap := make(map[string]bool)
			for _, rawFact := range strings.Split(args.Facts, ",") {
				fact := strings.TrimSpace(rawFact)
				if fact != "" {
					if !strings.HasPrefix(fact, platform+".") {
						fact = platform + "." + fact
					}
					factMap[fact] = true
				}
			}

			liveOutputs := map[string]string{}
			remoteUsed := false
			if args.Execute {
				if args.SSHTarget != "" {
					var err error
					liveOutputs, err = collectRemoteSSHPrivescFacts(ctx, args.SSHTarget, args.SSHUser, args.SSHPort, args.CredentialID, factMap)
					if err != nil {
						return nil, err
					}
					remoteUsed = true
				} else {
					liveOutputs = collectLocalPrivescFacts(ctx, platform, factMap)
				}
			}

			candidates := research.RankPrivileges(factMap)

			allTechniques := research.Techniques()
			var platformTechniques int
			for _, t := range allTechniques {
				if t.Platform == platform {
					platformTechniques++
				}
			}

			data := map[string]any{
				"platform":            platform,
				"candidates":          candidates,
				"facts_supplied":      len(factMap),
				"total_techniques":    platformTechniques,
				"escalation_executed": false,
				"host_inspected":      args.Execute,
				"remote_ssh_used":     remoteUsed,
				"limitation":          "Cerberus ranks techniques by configuration facts. When execute=true, runs read-only OS checks locally or over SSH to gather live facts. It does not execute privilege escalation.",
			}
			if args.Execute && len(liveOutputs) > 0 {
				data["live_os_outputs"] = liveOutputs
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Cerberus ranked %d privilege escalation candidates from %d %s techniques", len(candidates), platformTechniques, platform),
				Data:    data,
			}, nil
		},
	})
}

func collectLocalPrivescFacts(ctx context.Context, platform string, factMap map[string]bool) map[string]string {
	type osCmd struct {
		bin            string
		argv           []string
		key            string
		allowPartialOK bool // e.g. find exits 1 on permission denied despite stdout
	}
	var cmds []osCmd
	if platform == "linux" {
		cmds = []osCmd{
			{"id", nil, "id", false},
			{"uname", []string{"-r"}, "uname_r", false},
			{"find", []string{"/usr/bin", "/usr/sbin", "-perm", "-4000", "-type", "f"}, "suid_binaries", true},
			{"sudo", []string{"-n", "-l"}, "sudo_l", false},
		}
		// Only pass existing cron paths directly (no unexpanded glob without shell).
		var existingCron []string
		for _, candidate := range []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"} {
			if _, err := os.Stat(candidate); err == nil {
				existingCron = append(existingCron, candidate)
			}
		}
		if len(existingCron) > 0 {
			cronArgs := append(existingCron, "-writable")
			cmds = append(cmds, osCmd{"find", cronArgs, "writable_cron", true})
		}
		if _, err := os.Stat("/var/run/docker.sock"); err == nil {
			cmds = append(cmds, osCmd{"test", []string{"-w", "/var/run/docker.sock"}, "docker_sock_writable", false})
		}
	} else {
		cmds = []osCmd{
			{"whoami", nil, "whoami", false},
			{"whoami", []string{"/priv"}, "whoami_priv", false},
			{"net", []string{"localgroup", "administrators"}, "net_localgroup_admins", false},
			{"reg", []string{"query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s"}, "services_reg", true},
		}
	}

	liveOutputs := make(map[string]string)
	for _, c := range cmds {
		if ctx.Err() != nil {
			break
		}
		cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		cmd := exec.CommandContext(cmdCtx, c.bin, c.argv...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.Stdin = strings.NewReader("")
		err := cmd.Run()
		cancel()

		if c.key == "docker_sock_writable" && err == nil {
			liveOutputs[c.key] = "/var/run/docker.sock is writable"
			factMap["linux.docker.socket_writable"] = true
			continue
		}
		rawOut := stdout.Bytes()
		if len(rawOut) == 0 && err == nil {
			rawOut = stderr.Bytes()
		}
		if len(rawOut) > 0 && (err == nil || c.allowPartialOK) {
			output := strings.TrimSpace(string(rawOut))
			if len(output) > 2048 {
				output = output[:2048] + "... (truncated)"
			}
			liveOutputs[c.key] = output
			applyPrivescOutputFacts(c.key, output, factMap)
		}
	}
	return liveOutputs
}

func collectRemoteSSHPrivescFacts(ctx context.Context, sshTarget, sshUser, sshPort, credID string, factMap map[string]bool) (map[string]string, error) {
	if err := validateSimpleFlagValue(sshTarget, "ssh_target"); err != nil {
		return nil, err
	}
	if err := checkHost(ctx, sshTarget); err != nil {
		return nil, fmt.Errorf("cerberus_privesc ssh_target: %w", err)
	}
	if sshPort == "" {
		sshPort = "22"
	}
	if !validPort(sshPort) {
		return nil, errors.New("cerberus_privesc: invalid ssh_port")
	}
	if err := checkPort(ctx, sshPort); err != nil {
		return nil, fmt.Errorf("cerberus_privesc ssh_port: %w", err)
	}
	if err := validateSimpleFlagValue(sshUser, "ssh_user"); err != nil {
		return nil, err
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return nil, errors.New("cerberus_privesc: ssh client not found in PATH")
	}

	var keyFile string
	if credID != "" {
		services, _ := ctx.Value(servicesKey{}).(Services)
		if services.Credential == nil {
			return nil, errors.New("cerberus_privesc: credential service unavailable")
		}
		secret, cerr := services.Credential(credID, "ssh://"+sshTarget)
		if cerr != nil {
			return nil, cerr
		}
		if strings.Contains(secret, "PRIVATE KEY") {
			f, ferr := os.CreateTemp("", "rogue-ssh-*")
			if ferr != nil {
				return nil, ferr
			}
			keyFile = f.Name()
			_ = f.Chmod(0600)
			_, _ = f.WriteString(secret)
			f.Close()
			defer os.Remove(keyFile)
		}
	}

	dest := sshTarget
	if sshUser != "" {
		dest = sshUser + "@" + sshTarget
	}

	remoteChecks := []struct {
		key string
		cmd string
	}{
		{"id", "id"},
		{"uname_r", "uname -r"},
		{"sudo_l", "sudo -n -l 2>/dev/null || true"},
		{"suid_binaries", "find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null || true"},
		{"writable_cron", "find /etc/crontab /etc/cron.d /etc/cron.daily -writable 2>/dev/null || true"},
	}

	liveOutputs := make(map[string]string)
	for _, rc := range remoteChecks {
		if ctx.Err() != nil {
			break
		}
		args := []string{
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=10",
			"-o", "StrictHostKeyChecking=accept-new",
			"-p", sshPort,
		}
		if keyFile != "" {
			args = append(args, "-i", keyFile, "-o", "IdentitiesOnly=yes")
		}
		args = append(args, dest, rc.cmd)
		out, rerr := ProcessRunner{}.Run(ctx, sshBin, args)
		if rerr != nil && len(out) == 0 {
			liveOutputs[rc.key] = "error: " + rerr.Error()
			continue
		}
		output := strings.TrimSpace(string(out))
		if len(output) > 2048 {
			output = output[:2048] + "... (truncated)"
		}
		liveOutputs[rc.key] = output
		applyPrivescOutputFacts(rc.key, output, factMap)
	}
	return liveOutputs, nil
}

func applyPrivescOutputFacts(key, output string, factMap map[string]bool) {
	lOut := strings.ToLower(output)
	switch key {
	case "id":
		if strings.Contains(lOut, "(docker)") {
			factMap["linux.docker.group_member"] = true
		}
		if strings.Contains(lOut, "(lxd)") {
			factMap["linux.lxd.group_member"] = true
		}
	case "sudo_l":
		if strings.Contains(lOut, "nopasswd") && strings.Contains(lOut, "all") {
			factMap["linux.sudo.nopasswd_all"] = true
		}
		if strings.Contains(lOut, "setenv") {
			factMap["linux.sudo.setenv"] = true
		}
	case "suid_binaries":
		if strings.TrimSpace(output) != "" {
			if strings.Contains(lOut, "python") || strings.Contains(lOut, "perl") ||
				strings.Contains(lOut, "ruby") || strings.Contains(lOut, "php") {
				factMap["linux.files.suid_interpreter"] = true
			} else {
				factMap["linux.files.suid_shell"] = true
			}
		}
	case "writable_cron":
		if strings.TrimSpace(output) != "" {
			factMap["linux.cron.root_writable"] = true
		}
	case "net_localgroup_admins":
		if strings.Contains(lOut, "administrator") {
			factMap["windows.group.local_admin"] = true
		}
	case "whoami_priv":
		if strings.Contains(lOut, "seimpersonateprivilege") && strings.Contains(lOut, "enabled") {
			factMap["windows.token.impersonate"] = true
		}
		if strings.Contains(lOut, "sedebugprivilege") && strings.Contains(lOut, "enabled") {
			factMap["windows.token.debug"] = true
		}
		if strings.Contains(lOut, "seassignprimarytokenprivilege") && strings.Contains(lOut, "enabled") {
			factMap["windows.token.assign_primary"] = true
		}
		if strings.Contains(lOut, "sebackupprivilege") && strings.Contains(lOut, "enabled") {
			factMap["windows.token.backup"] = true
		}
		if strings.Contains(lOut, "serestoreprivilege") && strings.Contains(lOut, "enabled") {
			factMap["windows.token.restore"] = true
		}
	}
}

// ── TYPHON — payload encoding and delivery ────────────────────────────────────

func registerTyphon(registry *Registry) {
	registry.Register(&Tool{
		Name:     "typhon_encode",
		Category: "research",
		Internal: true,
		Description: "Encode a value using supported encoding formats (raw, url, " +
			"double_url, hex, base64, html, unicode). Also lists available payload " +
			"corpus statistics by family. When execute=true and target_url is set, " +
			"delivers the encoded value via HTTP GET — substitute ROGUE_INJECT in " +
			"the URL or the value is appended as query param 'q'. Does not confirm " +
			"WAF bypass or exploitability.",
		Parameters: researchSchema([]string{"value", "format"}, []string{"execute"}, "value", "format", "target_url", "execute"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Value     string
				Format    string
				TargetURL string `json:"target_url"`
				Execute   bool
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.Execute {
				if err := authorizeActive(ctx, "typhon_encode", raw); err != nil {
					return nil, err
				}
			}
			if len(args.Value) > 8192 {
				return nil, errors.New("value exceeds 8 KiB limit")
			}

			encoded, err := research.Encode(args.Value, args.Format)
			if err != nil {
				return nil, err
			}

			families := payloadFamilies()

			data := map[string]any{
				"encoded":            encoded,
				"input_length":       len(args.Value),
				"output_length":      len(encoded),
				"format":             args.Format,
				"available_formats":  []string{"raw", "url", "double_url", "hex", "base64", "html", "unicode"},
				"corpus_families":    families,
				"payload_delivered":  false,
				"waf_bypass_claimed": false,
			}

			if args.Execute && args.TargetURL != "" {
				targetURL := injectURL(args.TargetURL, encoded)
				status, body, probeErr := probeGET(ctx, targetURL)
				probeData := map[string]any{
					"url":             targetURL,
					"status":          status,
					"response_bytes":  len(body),
					"value_reflected": strings.Contains(body, args.Value) || strings.Contains(body, encoded),
				}
				if probeErr != nil {
					probeData["error"] = probeErr.Error()
				}
				data["payload_delivered"] = probeErr == nil
				data["delivery_probe"] = probeData
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Encoded %d bytes as %s (%d bytes output)", len(args.Value), args.Format, len(encoded)),
				Data:    data,
			}, nil
		},
	})
}

// ── GRIFFIN — credential harvesting / secret extraction ───────────────────────

func registerGriffin(registry *Registry) {
	registry.Register(&Tool{
		Name:          "griffin_secrets",
		Category:      "research",
		Internal:      true,
		SensitiveArgs: []string{"text"},
		Description: "Batch secret scanning across multiple text segments with " +
			"aggregated statistics. Uses 16 secret detection patterns with " +
			"redacted fingerprints. When execute=true and source_url is set, " +
			"fetches the URL content (up to 64 KB) and scans it for secrets in " +
			"addition to any supplied text segments. Pattern matches are not " +
			"verified live credentials.",
		Parameters: stringSchema([]string{"texts"}, "texts", "source_url", "execute"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Texts     string
				SourceURL string `json:"source_url"`
				Execute   bool
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}

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

			patternNames := make([]string, 0, len(secretPatterns))
			for _, p := range secretPatterns {
				patternNames = append(patternNames, p.name)
			}

			data := map[string]any{
				"segments":             results,
				"total_matches":        totalMatches,
				"category_counts":      categoryCounts,
				"patterns_available":   patternNames,
				"verified_credentials": false,
				"credential_tested":    false,
				"limitation":           "Griffin detects secret patterns by regex. When execute=true, also fetches source_url content for scanning. Matches are not verified live credentials.",
			}

			if args.Execute && args.SourceURL != "" {
				status, body, probeErr := probeGET(ctx, args.SourceURL)
				urlResult := map[string]any{"url": args.SourceURL, "status": status}
				if probeErr != nil {
					urlResult["error"] = probeErr.Error()
				} else {
					urlMatches := ScanSecrets(body)
					urlResult["response_bytes"] = len(body)
					urlResult["matches"] = urlMatches
					urlResult["match_count"] = len(urlMatches)
					totalMatches += len(urlMatches)
					for _, m := range urlMatches {
						categoryCounts[m.Kind]++
					}
				}
				data["url_scan"] = urlResult
				data["total_matches"] = totalMatches
				data["category_counts"] = categoryCounts
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Griffin scanned %d segments: %d potential secrets across %d categories", len(results), totalMatches, len(categoryCounts)),
				Data:    data,
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
			"requiring deeper investigation. When execute=true and target_url is " +
			"set, probes 12 common paths (/robots.txt, /.git/HEAD, /api, /admin, " +
			"/swagger.json, /health, /.env, etc.) via HTTP GET to discover " +
			"reachable surface. Does not exploit discovered paths.",
		Parameters: stringSchema(nil, "focus", "target_url", "execute"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				Focus     string
				TargetURL string `json:"target_url"`
				Execute   bool
			}
			_ = json.Unmarshal(raw, &args)

			services, _ := ctx.Value(servicesKey{}).(Services)
			// Surface service is optional — degrade gracefully when running outside engine context.
			var surface any
			if services.Surface != nil {
				surface = services.Surface()
			} else {
				surface = map[string]any{"note": "surface service unavailable in this context; supply target_url with execute=true to probe directly"}
			}
			families := payloadFamilies()
			chainTemplates := research.Chains()
			techniques := research.Techniques()
			platformCounts := make(map[string]int)
			for _, t := range techniques {
				platformCounts[t.Platform]++
			}

			data := map[string]any{
				"surface":                surface,
				"payload_families":       families,
				"chain_templates_count":  len(chainTemplates),
				"privesc_techniques":     platformCounts,
				"focus":                  args.Focus,
				"zero_day_discovered":    false,
				"automated_exploitation": false,
				"limitation":             "Simurgh maps attack surface from observed inventory. When execute=true, also probes common paths via HTTP GET. It does not exploit discovered paths.",
			}

			if args.Execute && args.TargetURL != "" {
				paths := []string{
					"/", "/robots.txt", "/.git/HEAD", "/.env",
					"/api", "/api/v1", "/admin", "/swagger.json",
					"/health", "/status", "/config", "/backup",
				}
				type pathResult struct {
					Path   string `json:"path"`
					Status int    `json:"status"`
					Bytes  int    `json:"response_bytes"`
					Error  string `json:"error,omitempty"`
				}
				base := strings.TrimRight(args.TargetURL, "/")
				probes := make([]pathResult, 0, len(paths))
				for _, p := range paths {
					status, body, probeErr := probeGET(ctx, base+p)
					pr := pathResult{Path: p, Status: status, Bytes: len(body)}
					if probeErr != nil {
						pr.Error = probeErr.Error()
					}
					probes = append(probes, pr)
				}
				data["path_probes"] = probes
				data["paths_probed"] = len(probes)
			}

			return &Result{
				Success: true,
				Summary: "Attack surface analysis with research gap identification",
				Data:    data,
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
			"coordinated assessment planning. When execute=true, runs up to 4 " +
			"concurrent HTTP GET probes against target_id URLs from the supplied " +
			"findings (target_id must be a full http/https URL). Does not confirm " +
			"exploitability.",
		Parameters: stringSchema([]string{"findings_json"}, "findings_json", "execute"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				FindingsJSON string `json:"findings_json"`
				Execute      bool
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

			cweToFamily := cwePayloadFamilies

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
				fams := cweToFamily[f.CWE]
				count := 0
				for _, p := range corpus {
					if containsString(fams, p.Family) {
						count++
					}
				}
				vectors = append(vectors, vector{
					TargetID:      f.TargetID,
					CWE:           f.CWE,
					Title:         f.Title,
					PayloadFamily: fams,
					PayloadCount:  count,
					Parallel:      true,
				})
				targetVectors[f.TargetID]++
			}

			parallelTargets := make(map[string]int)
			for target, count := range targetVectors {
				if count > 1 {
					parallelTargets[target] = count
				}
			}

			data := map[string]any{
				"vectors":          vectors,
				"parallel_targets": parallelTargets,
				"total_corpus":     len(corpus),
				"attacks_executed": false,
				"limitation":       "Hydra identifies parallel assessment vectors. When execute=true, runs up to 4 concurrent HTTP GET probes (target_id must be a full URL).",
			}

			if args.Execute && len(vectors) > 0 {
				limit := 4
				if len(vectors) < limit {
					limit = len(vectors)
				}

				type probeResult struct {
					TargetID string `json:"target_id"`
					CWE      string `json:"cwe"`
					Payload  string `json:"payload,omitempty"`
					Status   int    `json:"status,omitempty"`
					Bytes    int    `json:"response_bytes,omitempty"`
					Error    string `json:"error,omitempty"`
				}

				probes := make([]probeResult, limit)
				var wg sync.WaitGroup
				sem := make(chan struct{}, 4)

				for i := 0; i < limit; i++ {
					wg.Add(1)
					sem <- struct{}{}
					go func(idx int, v vector) {
						defer wg.Done()
						defer func() { <-sem }()

						pr := probeResult{TargetID: v.TargetID, CWE: v.CWE}
						if !strings.HasPrefix(v.TargetID, "http://") && !strings.HasPrefix(v.TargetID, "https://") {
							pr.Error = "target_id is not an http/https URL; skipping probe"
							probes[idx] = pr
							return
						}
						// Pick first raw payload for the first family
						var samplePayload string
						if len(v.PayloadFamily) > 0 {
							for _, p := range corpus {
								if p.Family == v.PayloadFamily[0] && p.Encoding == "raw" {
									samplePayload = p.Value
									break
								}
							}
						}
						pr.Payload = samplePayload
						targetURL := v.TargetID
						if samplePayload != "" {
							targetURL = injectURL(v.TargetID, samplePayload)
						}
						status, body, probeErr := probeGET(ctx, targetURL)
						pr.Status = status
						pr.Bytes = len(body)
						if probeErr != nil {
							pr.Error = probeErr.Error()
						}
						probes[idx] = pr
					}(i, vectors[i])
				}
				wg.Wait()

				data["attacks_executed"] = true
				data["probe_results"] = probes
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Hydra identified %d attack vectors across %d targets (%d with parallel paths)", len(vectors), len(targetVectors), len(parallelTargets)),
				Data:    data,
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
			"the same target and their validation preconditions. When execute=true, " +
			"verifies the reachability of up to 4 hypothesis targets via HTTP GET " +
			"probe. Does not execute exploit chains.",
		Parameters: stringSchema([]string{"findings_json"}, "findings_json", "execute"),
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var args struct {
				FindingsJSON string `json:"findings_json"`
				Execute      bool
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

			data := map[string]any{
				"chain_hypotheses":        candidates,
				"templates_available":     len(templates),
				"findings_analyzed":       len(inputFindings),
				"exploit_chain_confirmed": false,
				"exploit_chain_executed":  false,
				"limitation":              "Arachne builds chain hypotheses from CWE co-occurrence. When execute=true, verifies target reachability. Each hypothesis requires independent validation before any claim of a working chain.",
			}

			if args.Execute && len(candidates) > 0 {
				type verifyResult struct {
					ChainName string `json:"chain_name"`
					Target    string `json:"target"`
					Status    int    `json:"status,omitempty"`
					Bytes     int    `json:"response_bytes,omitempty"`
					Reachable bool   `json:"target_reachable"`
					Error     string `json:"error,omitempty"`
				}
				limit := 4
				if len(candidates) < limit {
					limit = len(candidates)
				}
				verifications := make([]verifyResult, 0, limit)
				for _, c := range candidates[:limit] {
					vr := verifyResult{ChainName: c.Template.Name, Target: c.Target}
					if strings.HasPrefix(c.Target, "http://") || strings.HasPrefix(c.Target, "https://") {
						status, body, err := probeGET(ctx, c.Target)
						vr.Status = status
						vr.Bytes = len(body)
						vr.Reachable = err == nil && status > 0
						if err != nil {
							vr.Error = err.Error()
						}
					} else {
						vr.Error = "target is not an http/https URL; skipping reachability probe"
					}
					verifications = append(verifications, vr)
				}
				data["precondition_verifications"] = verifications
			}

			return &Result{
				Success: true,
				Summary: fmt.Sprintf("Arachne found %d chain hypotheses from %d findings against %d templates", len(candidates), len(inputFindings), len(templates)),
				Data:    data,
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
