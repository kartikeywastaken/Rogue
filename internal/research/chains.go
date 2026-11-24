package research

import (
	"sort"
	"rogue/internal/domain"
)

type ChainTemplate struct{ID,Name string;RequiredCWEs []string;UnverifiedPrecondition string}
type ChainCandidate struct{Template ChainTemplate;Target,Status string;FindingIDs,EvidenceIDs []string}

func Chains()[]ChainTemplate{return []ChainTemplate{
	{"chain-01","Injection followed by data disclosure",[]string{"CWE-89","CWE-200"},"Verify query execution and data access on the same authorization boundary."},
	{"chain-02","Script injection and session exposure",[]string{"CWE-79","CWE-614"},"Verify browser execution and actual session exposure."},
	{"chain-03","Script injection and CSRF",[]string{"CWE-79","CWE-352"},"Verify a state-changing action with the required user interaction."},
	{"chain-04","SSRF and metadata exposure",[]string{"CWE-918","CWE-200"},"Verify server-side fetch and access to a permitted metadata endpoint."},
	{"chain-05","Traversal and credential exposure",[]string{"CWE-22","CWE-522"},"Verify file access and whether returned credentials are live."},
	{"chain-06","Upload and command execution",[]string{"CWE-434","CWE-78"},"Verify executable upload handling; no execution is inferred from acceptance."},
	{"chain-07","Template injection and command execution",[]string{"CWE-1336","CWE-78"},"Verify template evaluation and command-execution preconditions."},
	{"chain-08","XML entity expansion and disclosure",[]string{"CWE-611","CWE-200"},"Verify parser behavior and the source of disclosed content."},
	{"chain-09","Weak authentication and missing authorization",[]string{"CWE-287","CWE-862"},"Verify identity and access to the specific protected action."},
	{"chain-10","Credential exposure and authentication bypass",[]string{"CWE-522","CWE-287"},"Verify credential validity without broad login attempts."},
	{"chain-11","Predictable identifiers and object authorization",[]string{"CWE-330","CWE-639"},"Verify ownership boundaries with disposable test identities."},
	{"chain-12","Open redirect and token exposure",[]string{"CWE-601","CWE-200"},"Verify redirect behavior and whether tokens cross origins."},
	{"chain-13","Deserialization and code injection",[]string{"CWE-502","CWE-94"},"Verify a reachable deserializer and execution semantics."},
	{"chain-14","Writable service resource and privilege assignment",[]string{"CWE-732","CWE-269"},"Verify effective permissions and the privileged execution context."},
	{"chain-15","Search path and untrusted executable",[]string{"CWE-426","CWE-427"},"Verify the actual privileged loader search order."},
	{"chain-16","Race condition and access control",[]string{"CWE-362","CWE-863"},"Verify repeatable state transitions and authorization impact."},
	{"chain-17","Configuration exposure and authorization",[]string{"CWE-538","CWE-862"},"Verify exposed configuration and resulting protected access."},
	{"chain-18","Cross-origin trust and disclosure",[]string{"CWE-942","CWE-200"},"Verify browser origin checks and readable protected responses."},
}}

// Co-occurrence creates a research hypothesis, never a verified exploit edge.
func MatchChains(findings []domain.Finding)[]ChainCandidate{
	byTarget:=make(map[string][]domain.Finding)
	for _,finding:=range findings{byTarget[finding.TargetID]=append(byTarget[finding.TargetID],finding)}
	var candidates []ChainCandidate
	for target,items:=range byTarget{for _,template:=range Chains(){
		candidate:=ChainCandidate{Template:template,Target:target,Status:"hypothesis_requires_validation"};matched:=0
		for _,required:=range template.RequiredCWEs{for _,finding:=range items{if finding.CWE==required{matched++;candidate.FindingIDs=append(candidate.FindingIDs,finding.ID);candidate.EvidenceIDs=append(candidate.EvidenceIDs,finding.Evidence...);break}}}
		if matched==len(template.RequiredCWEs){candidates=append(candidates,candidate)}
	}}
	sort.Slice(candidates,func(i,j int)bool{if candidates[i].Target!=candidates[j].Target{return candidates[i].Target<candidates[j].Target};return candidates[i].Template.ID<candidates[j].Template.ID})
	return candidates
}
