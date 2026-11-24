# Rogue: four implementation phases

This is the implementation plan for [ARCH.md](ARCH.md) and the capability families
in [paper.md](paper.md). A phase is a milestone with multiple reviewable changes,
not a promise that its capabilities fit into one commit. Checked items describe
implemented behavior; unchecked items remain work. Architecture diagrams and role
prompts are not evidence of a working capability.

The existing terminal UI remains the presentation layer. Backend capabilities
must stream through `engine.Engine` without changes to its visual design. The
paper's browser War Room is a reference interface, not authorization to replace
or redesign this UI. A future additional browser client needs a separate scope
decision. Runtime mock options are explicitly excluded at the user's request;
local test fixtures remain necessary for repeatable verification.

## Phase 1 — reliable single-operator execution

**Outcome:** one operator can use a real provider and scoped tools with truthful
results, bounded execution, and observable failure.

- [x] Preserve the UI interface and remove production simulation/model choices.
- [x] Explicit OpenRouter, direct OpenAI, Groq, and local Ollama configuration.
- [x] Validate streamed tool-call completion and surface transport/protocol errors.
- [x] Return complete success/error envelopes to the model, including tool failures.
- [x] Enforce default/auto/plan, role capabilities, schemas, scope, and exclusions.
- [x] Check HTTP redirects and resolved peer IPs; enable certificate verification.
- [x] Fix A/AAAA resolution, cancellable TCP connections, bounded scanner workers,
  invalid port handling, and timeout/refusal/error classification.
- [x] Bound turns by deadline, model rounds, tool calls, and reported token usage.
- [x] Exercise execution and failure paths with deterministic local fixtures.
- [ ] Validate each selected live provider/model combination with real credentials
  and a controlled target; protocol fixtures do not prove a hosted model works.
- [x] Explicit capability probe for streaming, tool calls, and tool-result use;
  bounded pre-stream HTTP retries/backoff; explicitly configured fallback models;
  native Anthropic Messages support; per-request output caps and conservative
  token/spend reservations across attempts. Interrupted streams do not replay tools.

**Implementation status:** the Phase 1 implementation is complete. Live-provider
acceptance remains environment-dependent: the initial implementation had no
configured credentials. Later pair-specific validation is recorded in Phase 3;
general provider compatibility remains open. `--check-provider` provides
the controlled probe; local fixtures are not represented as hosted validation.

**Acceptance:** scoped reconnaissance returns real observations; denied calls have
no network side effects; broken streams cannot dispatch partial calls; stop and
limits produce truthful terminal outcomes. Live compatibility is documented per
provider/model rather than claimed globally.

## Phase 2 — shared mission infrastructure

**Outcome:** mission, evidence, and communication state have stable contracts and
are connected to the execution path, ready for multiple operators.

- [x] Mission lifecycle with validated transitions and isolated state per turn.
- [x] Priority tasks, atomic claims, pre-existing dependency validation, blocked
  descendants, configured phases, and completion guards.
- [x] A mission-scoped vault of tool observations with task/operator/call provenance.
- [x] Findings linked to successful observations, exact normalized-title/target
  deduplication, defensive snapshots, and redacted credential exports.
- [x] Direct/broadcast comms, mission isolation, ordered history, subscriptions,
  shutdown, and explicit all-or-none backpressure behavior.
- [x] Harness integration: Recon task -> tool observation -> vault -> comms ->
  terminal mission/task state, using existing UI events.
- [x] Concurrency and local end-to-end integration tests.
- [x] Authenticated encrypted checkpoints of missions, message history, evidence,
  private credentials, original tool artifacts, inventory, and spending. Atomic
  writes, per-process mission leases, interrupted-run recovery, and terminal-only
  retention avoid lost evidence or silently replayed operations.
- [x] Backend pause/resume/abort APIs with operation-level cancellation and a
  resume gate. Interrupted tool outcomes remain explicit observations. No new
  terminal UI controls or remote API are claimed.
- [x] TargetEnvironment address/service inventory, evidence-linked findings, a
  separate CVE reference catalog, recorded service conflicts with explicit review,
  task-based progress, and report-ready snapshots/inspection commands. CVE
  references do not automatically establish target applicability.

**Implementation status:** Phase 2 is implemented and locally validated through
mission completion, persisted reload, crash recovery/ownership checks, and
pause/resume. Multi-operator scheduling is described in Phase 3. Cross-turn model
context remains unimplemented; a saved report does not implicitly become input.

**Acceptance:** independent tasks can be claimed without double assignment;
failed dependencies block downstream work; unrelated missions cannot share state;
artifacts survive restart when persistence is enabled; every reported finding has
inspectable provenance. A successful tool call alone does not verify an exploit.

## Phase 3 — coordinated operators and assessment capabilities

**Outcome:** all eight roles participate in a supervised mission with useful,
measurable handoffs and actual capabilities appropriate to each role.

- [x] OperatorAgent/OperatorCell identities, capability sets, lifecycle, health,
  bounded concurrency, cooldown, and cancellation.
- [x] OpGeneral planning plus Coordinator supervision: validate proposed plans,
  dependencies, scope, budgets, and capabilities before dispatch.
- [x] First integrated workflow: Recon discovers -> Scanner checks discovered
  services -> Analyst reports evidence, with explicit failure/blocked handling.
- [x] Extend supported tasks to Exploiter, Infiltrator, Exfiltrator, and Ghost through
  controlled assessment/lab workflows, with explicit approval boundaries and real
  evidence. Report unsupported tasks as unsupported, never as completed actions.
- [x] Shared context retrieval and relevant comms delivery into operator inputs;
  follow-up tasks from evidence; duplicate/conflict handling and mission progress.
- [x] Implement bounded assessment variants of the paper's built-ins: subdomain enumeration, WHOIS,
  content discovery, technology identification, TLS checks, web vulnerability
  assessment, authentication assessment, hash analysis, Base64 and JWT utilities.
- [x] Bring forward the initial Nmap and curl adapters, typed inputs, executable
  availability checks, pinned target IPs, cancellation, bounded output, and raw
  Nmap XML evidence; NVD ID/keyword lookup with caching and pacing.
- [x] Expand the supported external tool catalog and connect service discovery/CPEs to
  candidate validation workflows. The initial adapters do not complete all tooling.
- [x] ApprovalController with decisions bound to exact action/target/mission,
  expiration, and audit; OPSEC detection tracking, thresholds, IOC records,
  pause/abort propagation, and operator cooldown/burn state.
- [x] AnalysisEngine: evidence-linked severity/CVSS/CVE/CWE metadata, observed access-path
  reasoning, remediation, executive/technical reports, Markdown and JSON exports.
- [x] Sixteen-pattern secret detection with redacted fingerprints and offsets.
- [x] Remaining research organs and large payload/reference datasets from paper §6.
  No fake implementations or simulated execution are registered for these modules.
  Nine organs (LEVIATHAN, SPHINX, GORGON, CERBERUS, TYPHON, GRIFFIN, SIMURGH,
  HYDRA, ARACHNE) are registered as real arsenal tools in the "research" category,
  backed by 200+ payloads, 50+ privesc techniques, 18 chain templates, 16 secret
  patterns, and live mission context. Each tool performs real analysis and
  explicitly disclaims execution or exploitability confirmation.

**Operational implementation:** a nine-task baseline covers eight roles, including
Coordinator planning and a second supervision step after Scanner. The supervisor
can propose evidence-backed prerequisites through `propose_task`; mission control
validates role, scope, dependencies, tool availability and budget before accepting.
Indexed `evidence_get` retrieves omitted observations without cross-mission access.
Observed services add up to four bounded Scanner tasks; their parent consolidates
without repeating network work. Workers transition through tasked, executing,
cooldown and burned states with cancellation and recorded failure-risk heuristics.

TLS, technology/cookie inspection, explicit path/DNS discovery and local utilities
are implemented. Exact-action expiring single-use backend approvals and explicit
detection/IOC logging with threshold pause have encrypted audit. Markdown/JSON
reports count evidence and retain uncertainty without invented CVSS scores.

Observed services now create up to four scoped Scanner prerequisites before the
main Scanner task. Context retrieval ranks ancestry, explicit citations, matching
targets and finding references before recency, with a configurable total JSON
size cap. `--assess` provides real headless acceptance runs and exports partial
reports on failure. Optional allowed ports constrain both native and external
network operations. These features are shared across providers.

**Live acceptance (2026-11-24):** a real local Juice Shop v20.4.0 release and
Groq `qwen/qwen3.8-27b` completed mission `854d11e7053f817c`: 9 tasks across
8 roles, 3 successful tool observations (Nmap, headers, technology), and 6
informational evidence-linked header findings. No mocks or simulated tool
responses were used. The encrypted mission reloaded and exported successfully.
Temporary Groq overrides and the longer-wait test binary have been archived
outside the project; normal provider/token defaults and source retry timing are unchanged.
This is scoped handoff validation, not comprehensive vulnerability coverage or
validation of every provider/model. Earlier provider/quota failures are retained.

**Provider-independent lab validation:** real Juice Shop checks completed for a
paired SQL-error probe (CWE-209 disclosure, not confirmed injection), reflection
probe, disposable-account authentication with encrypted credential capture,
session verification against an unauthenticated-denied endpoint, bounded response
collection and cleanup-marker verification. CVSS v3.1 calculation returned 9.8 for
the standard network/low-complexity/no-privilege/high-impact vector. No model API
was used for these checks. Role, port and lab-mode denials were checked separately.

Reports derive observed access paths from private evidence before redaction,
preserving raw-data confidentiality. CVE description correlations remain review
candidates; CVSS/CVE/CWE classification requires an explicit named review. Dig
joins the existing external adapters. Rate-limit signals can pause/abort through
configured OPSEC thresholds; generic failures are not described as detection.

**Remaining scope:** the paper's advanced research organs are now implemented as
nine analysis tools (LEVIATHAN, SPHINX, GORGON, CERBERUS, TYPHON, GRIFFIN,
SIMURGH, HYDRA, ARACHNE) backed by the reference datasets. Large payload corpus
(200+ encoded variants), privilege escalation ranking (50+ Linux/Windows
techniques), and chain hypothesis building (18 templates) are operational.
Arbitrary OS privilege escalation/persistence execution, unrestricted scanner
wrappers, and automatic confirmation of arbitrary CVEs remain out of scope.
The operational assessment backend and research catalog are delivered.

**Acceptance:** demonstrate multi-operator dependency handoffs against controlled
fixtures, measure completed/failed/blocked tasks and evidence quality, exercise
pause/abort and exhausted budgets, and show the Analyst's claims are grounded in
observations. Benchmarks must state whether they measure one agent or the cell.

## Phase 4 — integration, evaluation, extensibility, and operational delivery

**Outcome:** the completed harness can be embedded, evaluated, extended, and
operated through documented, tested interfaces.

- [ ] CLI mission/preset/configuration/report operations behind the existing TUI.
- [ ] HTTP API for missions, targets, operators, findings, tools, provider status,
  planning, and reports; authenticated event streaming with backpressure/replay.
- [ ] MCP stdio server and a TypeScript SDK, sharing backend policy and validation.
- [ ] Evidence/report export formats including PDF, scanner import (Nmap XML and
  Nuclei JSON), API/version compatibility, and integration tests.
- [ ] Controlled CTF range, benchmark categories, Cybench/NYU CTF adapters, reproducible
  fixtures, exact-result checks, calibrated judging, and regression thresholds.
- [ ] Plugin/tool extension contracts, hooks, knowledge retrieval, reasoning and
  cognition experiments, cloud assessment adapters, white-box analysis, and swarm
  experiments. Each must establish utility against the simpler baseline.
- [ ] Deployment/configuration, key management, telemetry, retention, recovery,
  performance, documented limitations, and release validation.
- [ ] Evaluate and explicitly specify the paper's long-term directions: distributed
  workers, hosted operation, tool/profile marketplace, remediation assistance, and
  continuous monitoring. These are separate deliverables within this phase and
  need deployment/product requirements; they are not implied by local interfaces.

**Acceptance:** interface and policy parity, reproducible benchmark reports,
recovery and concurrency tests, documented extension behavior, and release checks
for the actual supported deployments. Additional presentation surfaces remain
subject to the existing UI constraint.

## Source coverage

| Source area | Phase |
|---|---|
| ARCH interaction / CLI / HTTP / MCP / SDK | 4 |
| ARCH central orchestration / OpGeneral / OperatorCell | 2 foundation, 3 coordination |
| ARCH eight operators and AgentLoop | 1 loop, 3 operational roles |
| ARCH provider abstraction and local models | 1; provider resilience completed alongside 3 |
| ARCH Arsenal / tools / approvals / OPSEC | 1 enforcement, 3 expansion |
| ARCH shared evidence / communication / target context | 2 |
| ARCH reporting and complete multi-agent validation | 3 and 4 |
| Paper §§2–5 architecture, operators, phases, providers | 1–3 |
| Paper §§6–7 research catalogs and tool capabilities | 3 |
| Paper §§8–9 intelligence, reports, OPSEC | 2–3 |
| Paper §10 integration surfaces | 4 |
| Paper §11 browser UI reference | Existing TUI retained; separate client scope decision |
| Paper §12 benchmarks / CTF integration | 4 |
| Paper §13 scope, approval, credentials, data controls | 1–4 as applicable |
| Paper §14 comparison claims | Validate with evidence in 4; not implementation requirements |
| Paper §15 future directions | 3–4, explicitly specified before each delivery |
| Paper appendices | Capability inventory references, not reliable LOC/completion metrics |

## Reference and implementation decisions

Reference: [elder-plinius/T3MP3ST](https://github.com/elder-plinius/T3MP3ST),
particularly [MissionControl](https://github.com/elder-plinius/T3MP3ST/blob/main/src/mission/index.ts),
[EvidenceVault](https://github.com/elder-plinius/T3MP3ST/blob/main/src/evidence/index.ts),
[CommsChannel](https://github.com/elder-plinius/T3MP3ST/blob/main/src/comms/index.ts),
and [feature status](https://github.com/elder-plinius/T3MP3ST/blob/main/FEATURES.md).
The Go implementation uses the conceptual boundaries as reference; it is not a
copy of the TypeScript modules or their feature-completion claims.

Specific choices in this change:

- Mutex-owned mission state and atomic claims, rather than mutable task pointers.
- Existing-dependency references prevent cycles by construction; later-phase
  prerequisites are rejected. A future planner must topologically order task creation.
- Exact normalized titles plus targets deduplicate findings without stripping
  meaningful words such as "missing" or "enabled".
- Evidence requires successful observed tool execution and matching provenance.
  Findings are not extracted from unrestricted model prose or auto-stamped verified.
- Explicit backpressure errors replace silent loss. Message history is now
  checkpointed; live subscriber replay/acknowledgment remains later work.
  Backpressure currently fails the run rather than hiding an incomplete trace.
- One mission per UI turn preserves `/new` behavior without introducing hidden
  cross-turn memory or changing presentation.
- Configuration/schema errors are failures, not reasons to switch to simulation.
