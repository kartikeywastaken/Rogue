# Rogue

A Go security assessment harness with a Bubble Tea terminal interface. The current
runtime executes one Recon operator through a real streaming model provider and
four built-in network tools, installed Nmap/curl adapters, and public NVD CVE
lookup. Every turn owns an isolated mission, task queue, evidence vault, target
inventory, communication channel, and encrypted checkpoint.

The terminal layout, theme, wordmarks, and controls are preserved. There is no
production mock backend or simulated model choice. Missing configuration is a
startup error. Deterministic fixtures exist only in tests.

## Configuration

Set a provider, a tool-capable model available to that provider, and its credential.
Supply credentials through your environment or secret manager, not source files.

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
| `ROGUE_ALLOWED_TOOLS` | Optional tool-name allowlist; empty permits tools supported by the operator |
| `ROGUE_PREAPPROVED_TOOLS` | Explicit prior authorization for named tools in default mode |
| `ROGUE_TIMEOUT` | Mission deadline, default `3m` |
| `ROGUE_MAX_ITERATIONS` | Model rounds, default `15` |
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
./rogue --list-tools
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
internal/operator/          eight role profiles (Recon currently dispatched)
internal/domain/            shared assessment data types
internal/tui/               existing presentation and turn lifecycle
```

A useful reading path is `main.go` -> `engine/harness.go` -> `agent/loop.go` ->
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
