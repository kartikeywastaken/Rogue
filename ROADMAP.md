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
acceptance remains environment-dependent: no keys or model were configured during
this implementation, so that checkbox remains open. `--check-provider` provides
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
pause/resume. Cross-turn model context and multi-operator scheduling remain
Phase 3 work; a saved report does not implicitly become model input.

**Acceptance:** independent tasks can be claimed without double assignment;
failed dependencies block downstream work; unrelated missions cannot share state;
artifacts survive restart when persistence is enabled; every reported finding has
inspectable provenance. A successful tool call alone does not verify an exploit.

## Phase 3 — coordinated operators and assessment capabilities

**Outcome:** all eight roles participate in a supervised mission with useful,
measurable handoffs and actual capabilities appropriate to each role.

- [ ] OperatorAgent/OperatorCell identities, capability sets, lifecycle, health,
  bounded concurrency, cooldown, and cancellation.
- [ ] OpGeneral planning plus Coordinator supervision: validate proposed plans,
  dependencies, scope, budgets, and capabilities before dispatch.
- [ ] First integrated workflow: Recon discovers -> Scanner checks discovered
  services -> Analyst reports evidence, with explicit failure/blocked handling.
- [ ] Extend supported tasks to Exploiter, Infiltrator, Exfiltrator, and Ghost through
  controlled assessment/lab workflows, with explicit approval boundaries and real
  evidence. Report unsupported tasks as unsupported, never as completed actions.
- [ ] Shared context retrieval and relevant comms delivery into operator inputs;
  follow-up tasks from evidence; duplicate/conflict handling and mission progress.
- [ ] Implement the paper's remaining built-ins: subdomain enumeration, WHOIS,
  content discovery, technology identification, TLS checks, web vulnerability
  assessment, authentication assessment, hash analysis, Base64 and JWT utilities.
- [x] Bring forward the initial Nmap and curl adapters, typed inputs, executable
  availability checks, pinned target IPs, cancellation, bounded output, and raw
  Nmap XML evidence; NVD ID/keyword lookup with caching and pacing.
- [ ] Expand the external tool catalog and connect service discovery/CPEs to
  candidate validation workflows. The initial adapters do not complete all tooling.
- [ ] ApprovalController with decisions bound to exact action/target/mission,
  expiration, and audit; OPSEC detection tracking, thresholds, IOC records,
  pause/abort propagation, and operator cooldown/burn state.
- [ ] AnalysisEngine: evidence-linked severity/CVSS/CVE/CWE metadata, attack-path
  reasoning, remediation, executive/technical reports, Markdown and JSON exports.
- [ ] The paper's research tool catalogs, payload/reference datasets, secret-pattern
  detection, and advanced assessment modules, each with lab tests and an honest
  capability status. Catalog entries and simulators do not count as executed work.

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
