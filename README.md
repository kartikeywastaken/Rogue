# Rogue

A Go security assessment harness with a Bubble Tea terminal interface. The current
runtime connects eight roles through a dependency-aware assessment plan. Recon
and Scanner execute tools; four downstream specialists review evidence and
Analyst reports results. Registered capabilities include network checks,
installed Nmap/curl adapters, offline utilities, and public NVD CVE lookup.
Every turn owns an isolated mission, task queue, evidence vault, target
inventory, communication channel, and encrypted checkpoint.

The terminal layout, theme, wordmarks, and controls are preserved. There is no
production mock backend or simulated model choice. Missing configuration is a
startup error. Deterministic fixtures exist only in tests.

## Configuration

Set a provider, a tool-capable model available to that provider, and its credential.
Supply credentials through your environment or secret manager, not source files.

**Or configure from the TUI.** If no provider is configured, `go run .` opens a
setup screen: choose a provider, paste the API key (masked), enter a model ID,
then pick *save on this machine* or *this session only*. `/provider` reopens it
later to switch provider, key, or model. Saved keys go to
`<user config dir>/rogue/credentials.json` (macOS: `~/Library/Application Support/rogue/`)
with `0600` permissions, never the project tree. Environment variables always win
over saved values, a key from the environment is never copied to disk, and a
key file readable by other users is refused. `ROGUE_CREDENTIALS_FILE` moves the
file; `ROGUE_CREDENTIALS_FILE=off` disables it. Headless modes (`--assess`,
`--serve`, `--benchmark`, `--check-provider`) also read the saved file.

| `ROGUE_PROVIDER` | Required credential | Default API base |
|---|---|---|
| `openrouter` (default) | `OPENROUTER_API_KEY` | `https://openrouter.ai/api/v1` |
| `openai` | `OPENAI_API_KEY` | `https://api.openai.com/v1` |
| `groq` | `GROQ_API_KEY` | `https://api.groq.com/openai/v1` |
| `anthropic` | `ANTHROPIC_API_KEY` | `https://api.anthropic.com/v1` (native Messages API) |
| `ollama` or `local` | None | `http://localhost:11434/v1` |

`ROGUE_MODEL` is required. `ROGUE_MODELS` optionally supplies additional,
comma-separated model IDs for the existing model picker; the default model is
always first. `ROGUE_BASE_URL` overrides the API base. Hosted providers require
HTTPS. Local models must support streaming Chat Completions and function calls.
No models are downloaded or servers started automatically.

For example, after starting a local Ollama server and obtaining a suitable model:

```sh
export ROGUE_PROVIDER=ollama
export ROGUE_MODEL='your-installed-tool-capable-model'
export ROGUE_SCOPE='localhost,127.0.0.1,::1'
go run .
```

For Groq, set `ROGUE_PROVIDER=groq`, `GROQ_API_KEY`, and `ROGUE_MODEL` to an
available Groq model instead. The API adapter is exercised against local HTTP
fixtures; hosted credentials and individual deployed models require a live smoke
test in your own environment.

Run `./rogue --check-provider` after setting the provider and model. It checks
streaming, a harmless echo tool call, and the model using that tool result. It
contacts the configured model service and can consume provider credits; no
assessment target is contacted. Repeat it for each provider/model you intend to use.

`ROGUE_FALLBACK_MODELS` explicitly lists alternative models at the same provider.
`ROGUE_MODEL_RETRIES` defaults to `2` (range 0–3). Transient HTTP responses are
retried with bounded backoff and Retry-After support, before streaming begins.
Authentication errors and exhausted budgets stop fallback. A stream that fails
after starting is not replayed automatically. Direct Anthropic requests use its
native content blocks and named SSE events, with API version `2026-10-21`.

## Execution rules

Scope comes from explicit configuration, never from model text. `ROGUE_SCOPE` is a
comma-separated list of exact DNS names, IPs, or CIDRs. Subdomains require their
own entries. Pass an IP as the target when using a CIDR-only scope. An empty scope
allows model-only discussion but blocks all target network tools.

| Setting | Meaning |
|---|---|
| `ROGUE_EXCLUDED` | Hosts, IPs, or CIDRs denied even when otherwise in scope |
| `ROGUE_ALLOWED_PORTS` | Optional comma-separated TCP ports; empty keeps host-level scope |
| `ROGUE_ALLOWED_TOOLS` | Optional tool-name allowlist; empty permits tools supported by the operator |
| `ROGUE_PREAPPROVED_TOOLS` | Explicit prior authorization for named tools in default mode |
| `ROGUE_TIMEOUT` | Mission deadline, default `3m` |
| `ROGUE_MAX_ITERATIONS` | Model rounds, default `15` |
| `ROGUE_CONCURRENCY` | Active operators, default `2`, range `1–8` |
| `ROGUE_COOLDOWN` | Delay before reusing a worker, default `0s`, maximum `1m` |
| `ROGUE_CONTEXT_BYTES` | Shared context JSON cap, default `24576`, range `4096–131072` |
| `ROGUE_LAB` | Enable gated loopback lab tools; default `false` |
| `ROGUE_OPSEC_PAUSE_AFTER` | Recorded signal count before pause; `0` disables |
| `ROGUE_OPSEC_ABORT_AFTER` | Recorded signal count before abort; `0` disables |
| `ROGUE_MAX_TOOL_CALLS` | Executions attempted, default `64` |
| `ROGUE_MAX_TOKENS` | Per-mission token admission budget, default `50000` |
| `ROGUE_MAX_OUTPUT_TOKENS` | Output cap sent with each model request, default `2048` |
| `ROGUE_COST_LIMIT_USD` | Optional per-mission estimated spend limit |
| `ROGUE_INPUT_USD_PER_MILLION` | Explicit input price used for estimates |
| `ROGUE_OUTPUT_USD_PER_MILLION` | Explicit output price used for estimates |

Each HTTP attempt reserves a conservative input allowance plus its capped output
before sending. Completed requests with usage settle against reported counts;
failed or usage-less requests consume their full allowance. Retries and fallback
share the mission budget. Dollar estimates require both prices; configure the
highest applicable rates when fallback models differ. Without prices, reports
say pricing is unconfigured rather than pretending the requests were free.

These are local admission controls and estimates, not a guarantee about a
provider invoice: tokenizer framing, cached/reasoning tokens, and provider pricing
can differ. Account-side spend limits remain independent. The deadline and
iteration/tool limits also remain independent bounds.

- **default:** tools require explicit preapproval and still obey scope and role restrictions.
- **auto:** tools may execute within the configured scope and capability policy.
- **plan:** no tools are advertised or executed; the model can explain a plan.

For example, preapprove `dns_lookup,header_analysis` through
`ROGUE_PREAPPROVED_TOOLS` for a scoped reconnaissance run. The current UI has no
interactive approval protocol; an unapproved request returns an approval-required
observation rather than pretending approval was granted.

HTTP redirects and actual resolved socket peers are checked against scope.
Certificate verification is enabled. The port scanner uses up to 32 workers and
reports open, refused, timed-out, and error outcomes separately.

## Shared infrastructure and evidence

`MissionControl` supports start/pause/resume/finish/abort/fail, configured phases,
priority scheduling, atomic claims, dependencies, and blocked descendants.
The harness currently creates one Recon task. `PauseMission(id)` cancels the
in-flight model/tool operation and holds new work; `ResumeMission(id)` releases
the gate; `AbortMission(id, reason)` cancels the mission. Interrupted tools produce
an unsuccessful observation with an unknown outcome, never an automatic replay.
A paused model response is discarded and a new round can start after resume.
The wall-clock mission deadline keeps running while paused. These methods are
backend APIs for a future controller; no new UI controls were added. Esc still
cancels the turn. Progress reports count completed, failed, and blocked tasks;
completion of a task is not verification that the model achieved its objective.

`EvidenceVault` records tool input, the complete result envelope, timestamps,
mission/task/operator/call IDs, and target. Tool-produced findings require
successful observations with matching provenance. Missing headers are recorded as
informational observations requiring application-specific review, not confirmed
exploits. Duplicate target/title findings merge evidence references. Credential
exports redact secret values; raw network observations remain sensitive evidence.

`CommsChannel` supports registered members, direct messages, broadcast, ordered
history, subscriptions, and close/unsubscribe. Full subscriber queues reject the
whole publish with an explicit backpressure error; no partial delivery or silent
message loss occurs. New subscribers can inspect history for earlier messages.

State is concurrency-safe and checkpointed before tool dispatch, after its
observation, on lifecycle changes, and at completion. `TargetEnvironment` extracts
observed addresses/services and links findings to their source observations.
Conflicting service versions are retained for explicit `ReviewTarget` decisions.
Public CVE records form a separate reference catalog: a keyword hit never marks a
host vulnerable. Original Nmap XML is kept as a protected artifact while concise
structured services are supplied to the model.

`Harness.LastRun()` exposes the latest handles and `Report(id)` loads a redacted
report for active or persisted missions. Raw request/response bodies, artifacts,
and credential values are excluded from default report output. Model-generated
task summaries remain unverified text, not automatic findings.

Each UI turn is still a separate mission. Persisting a result does **not**
automatically add it to the next model request. Multi-agent scheduling and
cross-turn model context are Phase 3 work. `/new` remains a UI reset.

## External tools and CVE references

`./rogue --list-tools` shows availability without requiring model credentials.
The current registry has `dns_lookup`, `port_scan`, `http_request`,
`header_analysis`, `nmap_scan`, `curl_request`, and `cve_lookup`.

- `nmap_scan`: one authorized host, up to 256 explicit numeric ports, TCP connect
  scanning and light service/version discovery. It pins a checked IP, disables
  Nmap DNS, captures XML, and parses services/CPEs. Scripts, arbitrary command
  flags, shell execution, and automatic exploit checks are not exposed.
- `curl_request`: checked HTTP(S) URL, pinned IP, headers only, certificate checks,
  no redirects, no curl configuration, and no proxy inheritance.
- `cve_lookup`: exactly one CVE ID or product keyword, queried through NVD API 2.0.
  Results are capped and cached for one hour with bounded request pacing. Optional
  `NVD_API_KEY` enables the documented higher request allowance. This intelligence
  request uses the fixed NVD endpoint, not assessment-target scope; ordinary mode,
  preapproval, and capability policy still apply. A match remains unverified for
  the target until a later assessment establishes applicability.

Install binaries separately when needed. `ROGUE_NMAP_PATH` and `ROGUE_CURL_PATH`
can select installed executables. Missing programs are excluded from model tool
advertisements and return a clear availability error if directly requested. Child
processes receive a minimal environment without provider credentials. Output and
runtime are bounded. No tool installation or external scan is performed at startup.

## Durable state and recovery

`ROGUE_STATE_DIR` defaults to `.rogue/` in the working directory and is ignored by
Git. The directory is private (0700); the key and checkpoints are private (0600).
Checkpoints use AES-256-GCM authentication and encryption, atomic rename, and file
and directory sync. A process lease distinguishes a live mission from a crashed
one. A checkpoint can hold up to 32 MiB of mission state and raw evidence.

Normal application startup recovers unowned unfinished missions as aborted with
unknown unfinished outcomes, retaining all saved observations. It never restarts
network operations automatically. Inspection commands neither recover nor prune
existing missions.
Retention cleanup runs at normal startup: default `ROGUE_RETENTION_DAYS=30` and
`ROGUE_KEEP_MISSIONS=100`. Only terminal missions are eligible.

The local key protects saved data at rest; anyone with access to both the key and
checkpoints can decrypt them. Back up both together. A missing/corrupted key or
checkpoint causes an explicit error instead of silently deleting evidence.

```sh
./rogue --list-missions
./rogue --show-mission MISSION_ID
./rogue --show-mission MISSION_ID --report-format markdown
./rogue --assess 'Assess the configured target' --assessment-mode default
./rogue --list-tools
./rogue --capabilities
./rogue --check-provider
```

Mission inspection and tool availability do not require a model API key. The
capability probe does, except when using a running local model.

## Code map and review order

```text
main.go / config.go        startup, provider, policy, limits, inspection commands
internal/engine/            UI contract and mission composition root
internal/llm/               native providers, SSE, retries, fallback, probes, budget
internal/agent/loop.go      model -> validated tool batch -> observation -> repeat
internal/arsenal/           scoped built-ins, Nmap/curl runners, NVD lookup
internal/mission/           lifecycle, phases, task claims, dependencies, rules
internal/evidence/          observation provenance, finding dedup, secret redaction
internal/comms/             mission-scoped message routing and history
internal/target/            service inventory, conflicts, CVE reference catalog
internal/storage/           authenticated encrypted checkpoints and recovery
internal/operator/          profiles, cell capacity, lifecycle and health counts
internal/domain/            shared assessment data types
internal/tui/               existing presentation and turn lifecycle
```

A useful reading path is `main.go` -> `engine/plan.go` -> `engine/cell.go` -> `agent/loop.go` ->
`arsenal/arsenal.go` -> `arsenal/policy.go`, then the three shared services.
The two critical boundaries are `Engine` (presentation versus execution) and
`Provider` (agent behavior versus model transport).

```sh
git diff --stat
git diff -- main.go internal/engine/harness.go
git diff -- internal/agent/loop.go internal/arsenal

GOCACHE=/private/tmp/rogue-go-build go test ./...
GOCACHE=/private/tmp/rogue-go-build go test -race ./...
GOCACHE=/private/tmp/rogue-go-build go vet ./...
GOCACHE=/private/tmp/rogue-go-build go build -o rogue .
```

Checks use process/HTTP boundary fixtures and do not call hosted models or scan
external targets. Real loopback tests run where sockets are permitted and report
an explicit skip under a restrictive sandbox. Core encrypted recovery, lifecycle,
retry/budget, native protocol, parser, and adapter checks use no listening sockets.

## Coordinated assessment

OpGeneral installs a baseline plan: Coordinator reviews constraints, Recon discovers,
Scanner checks observed services, Coordinator supervises, four specialists run
within capacity, and Analyst consumes the handoffs. Nine baseline tasks cover eight roles sharing a
provider and mission budget. Failed tasks block descendants and fail the mission;
the saved report retains partial evidence. Access, post-access, exfiltration and
persistence roles can use approved bounded lab tools; arbitrary post-access
operations and persistence deployment are unsupported.

After Recon, up to four observed services create targeted Scanner prerequisite
tasks. These derive from successful inventory evidence and remain inside host and
port scope. The main Scanner task waits for them, then consolidates their evidence
without tool execution, preserving downstream handoffs without a second scan.
Coordinator can use `propose_task` to insert evidence-backed prerequisites before
Analyst. Mission control validates proposals; models cannot widen scope, grant
approval or bypass role/tool/budget restrictions. `evidence_get` retrieves exact
observations from this mission when bounded context omitted them.

Task input includes up to 20 ranked observations with bounded excerpts, direct
predecessor summaries labeled unverified, mission rules, and 12 recent addressed
messages and structured findings. Direct handoffs, matching targets and cited
evidence rank ahead of recency. The whole context envelope is size bounded;
execution facts carry authoritative observation and per-tool counts independently
of model-written summaries. Reports derive tool counts from the vault too;
truncation and omitted observation counts are explicit. Originals remain in the
encrypted vault. This
is within-mission context, not automatic cross-turn memory. Only Analyst prose
streams into the final answer; existing tool/status events show other workers.
Budgets include the whole cell, retries and fallback. Eight tasks can need more
time and tokens than Recon alone: configure `ROGUE_TIMEOUT` and `ROGUE_MAX_TOKENS`
accordingly. Exhaustion fails explicitly. `engine.Options.SingleOperator` retains
the real Recon baseline for embedding and comparisons.

New tools: `ssl_scan` verifies one TLS handshake/certificate; `technology_detect`
observes header hints and cookie flags without cookie values; `dir_bruteforce`
checks up to 16 explicit same-origin paths without redirects; `subdomain_enum`
resolves up to 32 labels, each separately scoped. `base64_decode` and `jwt_decode`
inspect bounded local input (JWT signatures remain unverified). `hash_crack`
compares up to 64 supplied SHA-256 candidates locally, returning a matching
index rather than plaintext. These tools do not establish exploitability.

Backend integrations can call `Harness.ApproveTool` with a mission ID, tool,
exact JSON arguments and expiration within one hour. Grants are single-use;
role, scope and allowlist checks still apply. Restart discards live grants;
encrypted comms retains audit. Grant before a task starts so its tool definitions
include the tool. There are no new terminal approval controls. `RecordDetection`
records an explicit observer signal/IOC and pauses at the supplied count threshold
(zero records only). Network errors are not automatically labeled detection.

JSON/Markdown reports count inspectable evidence and separate model reviews from
structured findings. CVSS v3.1 uses explicit vectors and FIRST's published base
equations; reviewed classifications retain their reviewer. CVE correlations are
candidates, not automatic applicability confirmation. Observed access paths use
authenticated/unauthenticated response pairs; no exploit chain is inferred from
co-located findings. OPSEC records explicit signals and HTTP 429 responses with
optional pause/abort thresholds; workers support burn and cancellation. Advanced
research organs and the large payload corpus remain unimplemented in ROADMAP.md.

`--assess` executes the same real engine without opening the terminal UI. Status
and tool summaries go to stderr; stdout contains the JSON or Markdown report.
Failed assessments export partial evidence and exit nonzero. Ctrl-C cancels the
mission through the same lifecycle controls. No mock backend is introduced.

`--tool NAME --operator ROLE --arguments -` reads a single JSON argument object
from stdin and executes the real tool without a model/API key. The explicit human
command grants only that exact action; role, host/port scope and lab gates still
apply. Its mission, results and any captured credentials use encrypted storage.
Use stdin for sensitive inputs to avoid putting them in process arguments.

Lab-only tools require `ROGUE_LAB=true`, a literal loopback IP, and an exact action
grant: `xss_scan` observes harmless marker reflection; `sqli_scan` compares one
syntax probe to a baseline; `password_spray` checks at most three supplied lab
accounts; `session_check` verifies one endpoint using a supplied/captured session;
`exposure_check` captures at most 64 KiB into the protected vault; `cleanup_verify`
checks a supplied marker without claiming cleanup was performed. These are
bounded assessment implementations, not general exploit/persistence engines.
`secret_scan` detects 16 potential secret patterns without returning values;
`cvss_score` scores a supplied v3.1 vector. WHOIS uses the fixed IANA endpoint;
`dig_lookup` wraps installed dig with fixed argv and time limits.

The normal 50000-token mission budget, provider selection and retry timing were
not changed for Groq. Historical test evidence remains; temporary Groq overrides
and test executables have been retired outside the project. CVSS reference:
[FIRST v3.1 specification](https://www.first.org/cvss/v3.1/specification-document).

## Keys

| key | action |
|---|---|
| enter | send |
| shift+enter / alt+enter / ctrl+j | newline |
| / | command palette (tab completes) |
| shift+tab | cycle default / auto / plan |
| esc | interrupt the running turn |
| up / down | prompt history |
| pgup / pgdn / wheel | scroll transcript |
| ctrl+c | quit |

Commands: `/help` `/model` `/mode` `/clear` `/new` `/quit`.

See [ARCH.md](ARCH.md) for the intended architecture and [ROADMAP.md](ROADMAP.md)
for the four implementation phases and explicit remaining work.
