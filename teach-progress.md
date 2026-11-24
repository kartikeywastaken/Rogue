# Rogue implementation learning record

## Session scope and baseline

- Goal: understand the implementation changes, their motivation, actual execution,
  design choices, failure cases, and broader impact well enough to explain and
  defend them in an interview.
- Mode: incremental change debrief; diagnose first, teach one stage, verify with
  fresh application, then advance. No time limit specified.
- Updated preference (2026-11-24): learner requested moving forward with Phase 2
  after the lesson became repetitive. Pause teaching without blocking development.
  Future requested debriefs should have a clear endpoint and a small, agreed
  question budget instead of an open-ended sequence of micro-checks.
- Repository: `/Users/kartik/Desktop/Rogue`.
- Git baseline: `4ea935e` (`inital setup`), current HEAD when teaching began.
- Assessed change: the assistant's tracked working-tree edits and new source,
  tests, and documentation since that commit. These changes are not committed.
- Initial source snapshot SHA256:
  `d217a14bdc3fd7ad2cf23aaff292b6708dd81931ac9e8cbfd749ff3a040105db`.
  Computed over sorted paths and bytes of main.go, main_test.go, ARCH.md,
  README.md, ROADMAP.md, and internal/**/*.go (33 files).
- Excluded from attribution and assessment: `.claude/` and `CLAUDE.md`, which
  appeared independently during implementation; generated binary and build cache.
- Constraints: preserve source and UI; only this learning record is edited.
  Any demonstrations must remain inside the sandbox and within authorized scope.
- Initial progress: no learner answers or demonstrated mastery at session start. Earlier
  assistant explanations and passing implementation tests are not learner evidence.

## Learning map and mastery criteria

Each item stays unchecked until the learner supplies independent evidence. Source
will be inspected again as each stage begins. This covers the changed behaviors
and the relevant unchanged contracts; it does not claim mastery of unimplemented
whitepaper capabilities or every dependency in the repository.

### 1. Architecture, motivation, and an end-to-end request

Sources: [startup](main.go), [engine contract](internal/engine/engine.go),
[UI submit](internal/tui/model.go#L317), [composition](internal/engine/harness.go),
[integration fixture](internal/engine/harness_test.go).

- [ ] Explain why the previous scaffold needed repair and distinguish model text,
  requested tool calls, executed operations, and evidence.
- [x] Establish that model prose alone provides no server observation. Q2:
  learner answered no and challenged what the model could be inspecting without
  a tool call. Source: AgentLoop text versus tool dispatch paths. This is narrow
  evidence; the full request flow and failed-tool distinction remain open.
- [x] Distinguish an attempted operation from successful header evidence. Q3:
  learner stated that Rogue returns the reason the request could not complete
  and leaves the header claim unsupported. Sources: header_analysis error path
  and AgentLoop's result feedback. Independent pass on 2026-11-24.
- [ ] Trace a prompt from UI request through backend execution to UI events;
  identify ownership across Engine, Harness, Provider, AgentLoop, and Arsenal.
- [x] Distinguish successful model communication from failed target execution.
  Q5: learner identifies the model side completing its job and Arsenal failing
  to contact the offline target. Reinforce that reporting failure is correct tool
  behavior; do not infer a bug from an unavailable target.
- [ ] Explain why backend changes can preserve the UI, including the unchanged
  interface and cancellation path they depend on.
- [x] Explain reuse of generic tool rendering. Q4: learner states no UI display
  code change is needed while the displayed tool name and status must reflect the
  actual call. Source: renderTool reads e.tool.Name, e.running, and e.tool.OK.
  Clarify that runtime display data changes, not a new tool-specific code branch.
- [ ] Distinguish what now runs from eight-role coordination and persistence that
  remain planned; explain why this distinction matters.

### 2. Startup, real providers, and streaming

Sources: [startup](main.go), [configuration](internal/llm/config.go),
[transport](internal/llm/client.go), [provider types](internal/llm/provider.go),
[startup tests](main_test.go), [protocol tests](internal/llm/client_test.go).

- [ ] Trace provider/model/credential selection, validation, catalog construction,
  and missing-config behavior; explain removal of silent mock fallback.
- [ ] Explain the HTTP request and SSE stream, streamed text, fragmented tool
  arguments, tool-call identity, and validated termination.
- [ ] Predict behavior on malformed JSON, unexpected EOF, provider errors,
  incomplete finish reasons, and cancellation; distinguish fixture-tested
  compatibility from unverified live-provider/model behavior.

### 3. Agent execution and stopping conditions

Sources: [loop](internal/agent/loop.go), [loop tests](internal/agent/loop_test.go).

- [ ] Trace the system/user/assistant/tool message sequence and ToolCallID linkage,
  including why tool results must be returned to the model.
- [ ] Explain full result envelopes and how the old Data-only path lost errors.
- [ ] Predict batch validation, duplicate-call rejection, observation callbacks,
  iteration/tool/token limits, and cancellation; explain the limits of reported
  token accounting and why limit exhaustion is not successful completion.

### 4. Arsenal policy and networking

Sources: [registry](internal/arsenal/arsenal.go),
[policy](internal/arsenal/policy.go), [rules](internal/mission/rules.go),
[network tools](internal/arsenal/recon.go), [tests](internal/arsenal/recon_test.go).

- [ ] Explain schema, role, tool allowlist, mode, preapproval, scope, and exclusion
  checks, and why model-visible descriptions do not enforce authorization.
- [ ] Trace DNS A/AAAA selection, actual-peer validation, redirects, TLS checking,
  response bounds, and the distinction between observations and vulnerabilities.
- [ ] Explain the scanner worker pool, cancellation, port validation, and separate
  open/refused/timeout/error outcomes; defend the bounded-concurrency choice.

### 5. MissionControl and task coordination

Sources: [control](internal/mission/control.go),
[tests](internal/mission/control_test.go).

- [ ] Trace allowed mission/task transitions, timestamps, pause, abort, failure,
  completion, and the distinction between dispatch policy and in-flight I/O.
- [ ] Explain priority scheduling, atomic claims, operator availability,
  dependency validation, blocked descendants, and phase completion guards.
- [ ] Explain mutex ownership, defensive snapshots, and per-turn mission isolation;
  defend these choices and identify the persistence/lifecycle work still pending.

### 6. EvidenceVault and CommsChannel

Sources: [vault](internal/evidence/vault.go), [vault tests](internal/evidence/vault_test.go),
[comms](internal/comms/channel.go), [comms tests](internal/comms/channel_test.go),
[wiring](internal/engine/harness.go), [domain types](internal/domain/domain.go).

- [ ] Distinguish a tool observation, a finding, and verified exploit evidence;
  trace mission/task/operator/call/target provenance into a stored finding.
- [ ] Explain deduplication, defensive copying, credential redaction, and why
  successful execution does not establish an exploitable vulnerability.
- [ ] Trace direct/broadcast routing, history order, membership, subscriptions,
  close/unsubscribe, and all-or-none backpressure behavior.
- [ ] Explain how the three shared services connect today and what future
  multi-operator context sharing still requires.

### 7. Verification, tradeoffs, and integrated interview assessment

Sources: [integration tests](internal/engine/harness_test.go),
[UI tests](internal/tui/model_test.go), [README](README.md), [architecture](ARCH.md),
[roadmap](ROADMAP.md), [reference paper](paper.md).

- [ ] Explain what unit, local integration, race, vet, build, and startup checks
  establish and what they do not; distinguish test fixtures from production mocks.
- [ ] Map changed files to user-visible behavior and the four phases; distinguish
  implemented, tested, live-unverified, and planned features.
- [ ] Independently trace an unfamiliar scenario spanning request, policy, tool
  outcome, mission/task state, evidence, comms, and UI feedback.
- [ ] Defend an actual design tradeoff and explain consequences of changing an
  invariant, without relying on memorized terminology.

## Module review state

| Key | Stage | Status | Evidence/gap | Last independent pass | Next review |
|---|---|---|---|---|---|
| architecture | 1 | learning | Q2–Q5 passed narrowly; Harness/run lifetime and cancellation pending | Narrow Q2–Q5 passes: 2026-11-24 | Full-module review after demonstration |
| providers-streaming | 2 | unseen | Not assessed | None | After demonstration |
| agent-loop | 3 | unseen | Not assessed | None | After demonstration |
| tools-policy-network | 4 | unseen | Not assessed | None | After demonstration |
| mission-control | 5 | unseen | Not assessed | None | After demonstration |
| evidence-comms | 6 | unseen | Not assessed | None | After demonstration |
| integration-ownership | 7 | unseen | Not assessed | None | After demonstration |

Default review scheduling after independent demonstration is next local calendar
day, then 3/7/14 days after later independent review passes. No automation or
reminder is scheduled by this record.

## Questions and attempts

### Q1 — initial architecture teach-back

- Stage: 1; diagnostic baseline, not a scored gate.
- Question: In your own words, what do you think happens between typing
  "check the headers on my local test server" into Rogue and seeing the result?
  In that explanation, describe what you think the model does and what the Go
  program does. Rough arrows or "I don't know" are welcome.
- Source inspected: main.go; internal/engine/engine.go;
  internal/tui/model.go submit; internal/engine/harness.go;
  TestRealHarnessWorkflow in internal/engine/harness_test.go.
- Attempt: learner answered "i dont know".
- Grade: diagnostic baseline — not yet demonstrated; no incorrect belief inferred.
- Assistance: no lesson or answer supplied for this diagnostic.
- Follow-up: start with model output versus Go-executed tool operations. Explain
  a simplified local-header request and show AgentLoop's actual Arsenal.Exec call.

### Q2 — language versus execution

- Stage: 1; criterion: distinguish model prose from an actual executed operation.
- Lesson: the model can request a tool by name and arguments; Rogue validates and
  executes the Go function, then supplies its result to the model. Use the actual
  header_analysis tool and the execution call in internal/agent/loop.go.
- Question: Suppose the model writes "I checked your server; it is missing a
  security header," but returns no tool call. Has Rogue actually contacted that
  server during this turn? Explain why.
- Scenario assumption: this is the first model response of the turn, and no
  earlier tool call has executed in the turn.
- Source inspected: internal/agent/loop.go model call, text handling, tool
  dispatch, and RoleTool observation; internal/arsenal/recon.go header_analysis.
- Attempt (2026-11-24): "nope, halucaintaion must not be true without tool call
  what is it inspecting?"
- Grade: pass for the narrow criterion. Learner correctly rejected the inspection
  claim and identified the absent observation source.
- Clarification to teach: unsupported does not necessarily mean factually false;
  the statement could accidentally be correct, but this turn did not establish it.
- Assistance: introductory lesson provided before question; no answer supplied
  for this scenario. Assess the learner's causal explanation, not copied terms.

### Q3 — a requested tool that fails

- Stage: 1; criterion: distinguish a requested action from a successful observation.
- Lesson: a tool call is a structured request. Permission checks or execution can
  fail. Show header_analysis's actual Success:false error result and explain that
  failure information is returned to the model.
- Question: The model requests header_analysis for your permitted local server.
  Rogue attempts the request, but the connection is refused and no HTTP response
  arrives. What can Rogue truthfully report, and what can it conclude about the
  server's security headers?
- Source: internal/arsenal/recon.go:366; internal/arsenal/arsenal.go:113;
  internal/agent/loop.go:262 and RoleTool message construction.
- Attempt (2026-11-24): "it will return the error what made it unable to complete
  the request calim will be left unsupported".
- Grade: pass. Correctly identifies both the available failure observation and
  the lack of support for a security-header conclusion.
- Assistance: introductory failure-path lesson; no answer supplied for this
  concrete scenario.

### Q4 — adding a tool behind the unchanged UI contract

- Stage: 1; criterion: explain request/event separation and why backend features
  can reuse the existing UI.
- Lesson: UI submit constructs Request{Prompt, Model, Mode} and calls Engine.Run;
  the backend returns an event channel. UI rendering handles text, tool-start,
  tool-end, notice, error, and done events. Engine is an existing interface; the
  Harness implements it and hides provider/network/state mechanics.
- Question: Suppose we later add a tool named whois_lookup and its progress uses
  the existing tool-start/tool-end event format. Would adding that tool require
  changing the UI's rendering code? Explain using the request/event boundary.
- Scenario: hypothetical future tool, not a claim it is implemented.
- Source: internal/tui/model.go:343 and onEvent; internal/engine/engine.go:76;
  internal/engine/harness.go:64; main.go:25. The Engine method contract is unchanged
  from the Git baseline; only its introductory comment changed.
- Attempt (2026-11-24): "no we wont need the change the UI code in its display ,
  for rendering if we disply the tool name then yea we will have to show which
  tool was called up and what was the status".
- Grade: pass for generic rendering reuse. Interpret the final clause as changing
  the displayed data at runtime, consistent with the learner's explicit statement
  that UI code need not change; do not infer an incorrect tool-specific branch.
- Clarification: renderTool already obtains the tool name and status from each
  event's fields. No hardcoded new-name case is required for this scenario.
- Assistance: introductory contract lesson; no answer supplied for this scenario.

### Q5 — model transport versus target tool execution

- Stage: 1; criterion: distinguish the Provider/model conversation from the
  Arsenal/target operation within the request flow.
- Lesson: Provider sends messages/tool definitions to the configured model API
  and returns text/tool requests. Arsenal dispatches Go tool implementations,
  which contact the assessment target. AgentLoop connects the two and returns
  tool outcomes to the model. UI names/statuses are already data-driven.
- Question: Rogue successfully receives a header_analysis request from the model,
  but your local test server is offline. For this round, which part has completed
  its communication successfully, Provider or Arsenal, and which reports the
  target-operation failure? Explain the difference between their destinations.
- Sources inspected: internal/llm/client.go:62 and :78;
  internal/llm/provider.go:75; internal/agent/loop.go:145 and :256;
  internal/arsenal/arsenal.go:94; header_analysis target HTTP request inspected
  in Q3. Rendering clarification: internal/tui/view.go:230.
- Attempt (2026-11-24): "the model did its job but the arsenal coudlnt since the
  server was offline".
- Grade: pass for distinguishing the successful model-side communication from
  the target-operation failure. Exact component names are not required when the
  causal distinction is correct.
- Clarification: Arsenal still behaves correctly when it returns a truthful
  failure result for an offline target.
- Assistance: introductory component-responsibility lesson; no scenario answer
  supplied before the learner's submission.

### Q6 — visible transcript versus backend run context

- Stage: 1; criterion: explain Harness-owned run lifetime and the current limit
  on cross-turn context.
- Lesson: Harness creates a new mission ID, MissionControl, EvidenceVault, and
  CommsChannel for each submitted turn. MissionControl tracks work, EvidenceVault
  retains observations/findings, and CommsChannel routes mission messages.
  AgentLoop starts with the configured system message and current user task.
  The UI transcript persists visually but is not passed as message history.
- Question: You inspect server A, then submit "What did we find earlier?" as a
  new turn. Does the visible UI transcript guarantee that the model receives
  server A's results? Explain using the current per-turn setup.
- Sources: internal/engine/harness.go:108–115; internal/agent/loop.go:125–129;
  internal/tui/model.go:343; TestRealHarnessWorkflow's later-turn isolation check.
- Attempt (2026-11-24): "if the model hasnt hallucinated then yes it must have
  passed all of the compoments that is missioncontrol evidencevalut and
  commschannel to do actual communication".
- Grade: partial. Learner recalls mission/evidence/comms infrastructure, but
  answers whether an earlier operation was genuine rather than whether its
  result is included in the next model request. Cross-turn context criterion
  remains unchecked.
- Gaps: visible UI transcript and stored observations do not automatically enter
  model messages; CommsChannel is internal mission messaging, not the target
  network client. Prior Q2–Q5 narrow evidence remains valid; recheck these new
  distinctions instead of erasing demonstrated facts.
- Assistance: introductory run-ownership lesson; no concrete scenario answer
  supplied before submission.

### Q7 — design an evidence-grounded follow-up input

- Stage: 1; remediation for Q6, fresh application rather than repeating yes/no.
- Lesson: distinguish display, storage, and model input. A result can be genuine
  and visible in the UI while absent from the next request's messages. Current
  AgentLoop initializes only system instructions and the current user task.
  Provider contacts the model; Arsenal tools contact targets; CommsChannel routes
  internal messages and does not automatically supply model context.
- Question: Suppose we want a new turn to answer "Which security header was
  missing earlier?" accurately, without inspecting the server again. What
  information should the backend include in that new model request?
- Scenario: proposed behavior for explanation only; no implementation authorized.
- Sources: internal/tui/model.go:343; internal/agent/loop.go:125;
  internal/llm/client.go:58; internal/engine/harness.go:108;
  internal/comms/channel.go Publish.
- Attempt (2026-11-24): "it would look into the previous turn report output then
  see what was missed and what went wrong".
- Grade: partial. Correctly identifies previous-run output as relevant. Still
  needs to distinguish an assistant report from actual tool observations and
  explain that the backend must explicitly include retrieved information in the
  next model request. Do not assume "it" means automatic model access.
- Assistance: Q6 corrected before this new design-application question; do not
  count a repetition of the Q6 answer as a fresh independent demonstration.

### Q8 — choose evidence when an old report conflicts with a tool result

- Stage: 1; integrated repair of Q6–Q7 before advancing.
- Lesson: retrieve the relevant prior tool observation with its target and
  success/error outcome, then explicitly include it in the model's messages.
  An assistant report is a summary and may misstate evidence. Retrieval alone
  does not guarantee the model's final answer is correct. This retrieval is a
  proposed extension; the current implementation does not do it across turns.
- Question: Imagine an earlier run contains a tool result saying
  "success: false; error: connection timed out" and an assistant summary saying
  "CSP is missing". To answer a later follow-up accurately, which information
  should the backend provide as evidence in the new model request, and what can
  the model truthfully conclude about CSP?
- Sources: Observation fields in internal/evidence/vault.go:17;
  provenance validation in AddFinding; internal/engine/harness.go OnTool;
  internal/llm/client.go chatRequest.Messages and ChatStream.
- Scenario: hypothetical conflicting report; no claim this happened during an
  executed live run.
- Attempt (2026-11-24): "it would provide with the tool result the error and the
  summary".
- Grade: partial for the full question; correct selection of the actual tool
  result and error. The role of the old assistant summary and the CSP conclusion
  were not explicit. Do not assume the learner treats summary text as verified.
- Feedback: an assistant summary may be carried as labeled, unverified context;
  the timeout is the actual observation, and CSP status was not determined.
  The learner already independently established the failed-request limitation
  in Q3, so avoid another redundant failure-versus-header quiz.
- Assistance: corrected Q7 with explicit retrieval-to-messages and
  observation-versus-summary distinctions before this fresh conflicting-input case.

### Q9 — explicit argument flow into ChatStream

- Stage: 1; focus the remaining cross-turn-input gap on actual code.
- Lesson: AgentLoop passes msgs to Provider.ChatStream; the provider serializes
  msgs as the API request's Messages field. Merely storing or loading information
  in the process does not establish that it was an input to this call.
- Question: Suppose a future retrieval step loads an old observation into a
  variable called previousResult, but msgs still contains only the system
  instructions and current question. Does this ChatStream call receive the old
  observation? Explain by following the value it sends.
- Displayed code: stream, err := l.llm.ChatStream(ctx, cfg.Model, msgs, tools).
- Scenario: proposed retrieval step, not implemented code.
- Sources: internal/agent/loop.go:125 and :145; internal/llm/client.go:30 and :58.
- Attempt: deferred when learner requested moving forward with Phase 2.
- Grade: not assessed; no mastery inferred from deferral.
- Assistance: targeted data-flow explanation following Q8; no scenario answer
  supplied before submission.

## Current position

- Status: paused at learner's request to move forward with Phase 2.
- Stage: 1, architecture and request flow.
- Deferred: Q9; resume only if the learner wants to return to this topic.
- Verified criteria: Q2, model prose alone provides no server observation; Q3,
  failed execution supports an error report but not a header assessment.
  Q4: UI rendering is reusable while tool-specific display data changes.
  Q5: model communication success does not establish target-tool success.
- Baseline: learner does not yet know the request/execution flow; assume no Go
  interface or agent-framework prerequisites until demonstrated.
- Remaining stage-1 gaps: explicit cross-turn evidence transfer, reports versus
  observations, internal comms versus network I/O,
  Harness/run ownership, cancellation boundary, complete component trace, rationale
  for repairs, and implemented versus planned architecture.
- Next action: return to development planning. Phase 2 foundations are implemented;
  remaining work is durable storage/recovery, live lifecycle propagation, and
  TargetEnvironment/evidence synchronization. Do not gate that work on Q9 or
  require another quiz. Preserve unchecked learning criteria for optional review.
- Implementation defects discovered during teaching: none assessed yet; any
  later finding is recorded here for a separately authorized fix.

## Implementation update — Phase 1/2 completion work (2026-11-24)

The learning session remains paused; the user prioritized implementation quality
and a brief explanation of the next milestone. No new quiz or mastery claim is
introduced by this update. The source has expanded since the initial assessment
snapshot, so review the current code before resuming affected modules.

New material for a future bounded debrief:

- Provider retries, explicit fallback, native Anthropic streaming, capability
  probing, output caps, and conservative request-budget reservations.
- AES-GCM encrypted checkpoints, process ownership leases, crash recovery without
  automatic tool replay, retention, and redacted inspection commands.
- Pause/resume/abort propagation through operation contexts and preserved
  interrupted tool outcomes.
- Target inventory, service conflicts/review, task-based progress, a separate CVE
  reference catalog, and protected original Nmap XML.
- Scoped Nmap/curl adapters and cached, paced NVD ID/keyword lookup.

The prior lesson's cross-turn limitation still holds: persisted observations do
not automatically become input to the next model request. Multi-operator context
sharing and coordination remain Phase 3 work. Live model acceptance remains
unverified in this environment because no keys or model are configured.

## Session 2 — commit history + pending eight-role change (2026-11-24)

- Goal: bounded debrief of commits 92a046d (tui), d5b0649 (font/docs),
  4ea935e (initial setup), f6ac1a2 (phasec3), and the uncommitted eight-role
  dependency workflow. Focus: architecture and guardrails (scope enforcement,
  exact-action approvals, shared budgets, evidence provenance, pause/abort).
- Scope limit: explain and quiz only; no source edits; no work that extends
  offensive capability.
- Budget (per learner preference for a clear endpoint): 5 stages, one
  question each, plus one optional integrated scenario. Then close.
- Snapshot: HEAD f6ac1a2 plus working tree. SHA256 over sorted modified and
  untracked .go files: 09e6ffdd…4ab026. The tree was still changing during the
  session (cell_test.go, report.go, store.go and main.go changed after the
  first read). Re-check source before grading any stage it affects.

### Stage map

- [ ] S1. Single-call guardrail pipeline: Registry.Exec order
  (Available → validateArgs → authorize → Execute), and why the pending change
  moved validation ahead of authorization. Sources: internal/arsenal/arsenal.go:97–114,
  internal/arsenal/policy.go:29–56.
- [ ] S2. Exact-action approvals: actionKey canonicalization, single use, a
  maximum one-hour expiry, deliberate loss on restart, audit through comms.
  Sources: internal/engine/approval.go:20–97.
- [ ] S3. Scope at the network layer: scopedDial resolves, then validates each
  IP, then dials the literal IP. Also redirect re-checks and DNS rebinding.
  Source: internal/arsenal/policy.go:79–122.
- [ ] S4. Fixed dependency plan and dispatch: AssessmentPlan graph, Claim,
  blockDependents, and tool-less review roles. Sources: internal/engine/plan.go,
  internal/engine/cell.go dispatch/executeTask, internal/mission/control.go Claim/blockDependents.
- [ ] S5. Shared budget and untrusted context: mission-wide toolCalls in
  BeforeTool versus per-loop limits; taskContext labels predecessor summaries
  as unverified. Source: internal/engine/cell.go BeforeTool and taskContext.
- [ ] Optional integrated scenario.

### Attempts

#### S1-Q1 — baseline (pending)
- Question: see chat. Asked 2026-11-24. Awaiting learner.
