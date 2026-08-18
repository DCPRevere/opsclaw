# OpsClaw — Design

How OpsClaw gets built. `OPSCLAW_BRIEF.md` is the reference for intent; this
document is the reference for architecture. The third input is
`~/src/dcprevere/gianna.chat` — a production Rust agent whose patterns (and
documented production incidents) we adopt wholesale where they fit. Where this
doc says "gianna lesson", the pattern earned its place in prod; don't redesign
it without a reason.

## 1. System shape

One team runs **one daemon**. The daemon is the team's agent: it owns the
heartbeat loop, the SQLite store, the memory bank, incidents, approvals, and
the audit chain. Operators reach it through the web UI it serves (embedded
in the binary, gianna-style), Telegram, a remote CLI (token-auth against the
daemon's gateway, gianna's `gcli_` pattern), or the local CLI on the same
host. **Team-shared memory falls out of this
shape for free** — one daemon = one memory store, with per-operator
attribution on everything said, approved, or learned. Multi-daemon federation
is explicitly out of scope; if a team ever needs two daemons, that's a
Postgres-backend problem for later, and the repo traits keep it cheap.

The daemon is **single-tenant**: one team, one config. No tenancy ids thread
through the code (gianna's household boundary has no analog here); the
isolation boundary that matters is per-target authorization at the policy
choke point. Policy attributes — autonomy, escalation, notification
routing — resolve down the tree, target overriding env overriding project;
**credentials never inherit** (brief invariant #5).

Single library crate, thin binaries (gianna pattern — the CLI drives the same
orchestrator path as every channel, zero duplicated logic):

- `opsclaw` — daemon + gateway
- `opsclaw-cli` — onboard, config wizards, chat REPL, estop, incidents,
  postmortem, doctor, runbook, memory. Local mode links the library directly;
  remote mode speaks to the daemon's gateway with a token.

## 2. Module layout

```
domain/      Project, Environment, Target, Resource, Autonomy, RiskClass,
             Incident, ApprovalRequest, Runbook — pure types
config/      TOML at ~/.opsclaw/config.toml + env; secret store (aes-gcm,
             key file); validate() fails fast; Debug redacts secrets
db/          trait-per-repo; SQLite impl + in-memory fake; parity suite
llm/         LlmProvider trait; Anthropic + OpenAI-compat impls; FallbackLlm;
             FakeLlm + ScriptedLlm doubles; usage/cost tracking
agent/       tool loop, prompt assembly, token-budgeted replay window
tools/       Tool trait (self-declared risk class + capability metadata);
             ssh/kubernetes/monitor/systemd/docker/...; endpoint tools
targets/     TargetExecutor trait per target type (ssh/local/kubernetes/cloud);
             connection lifecycle; credential resolution by name
policy/      THE choke point: risk classification, e-stop, autonomy gates,
             rate/cost caps, approval routing — one function every remote
             command passes through
audit/       hash-chained append-only log, written by policy/, no bypass
scheduler/   heartbeat loop, scan jobs, escalation chain, approval timeouts,
             dead-man's switch
incidents/   fingerprinting, dedup claims, lifecycle, postmortem
memory/      Memory trait; Hindsight client (gianna's, generalized); shared
             team bank; attribution; recall in tool loop
channels/    Channel trait; Telegram, web (SSE), webhook-out, CLI; MultiChannel
http/        gateway + embedded web UI (chat, incidents/approvals, status,
             config management); operator accounts/auth; alert webhooks in;
             remote-CLI API
runbooks/    parse (TOML front matter + markdown), match, execute, track
cli/         clap; wizards; every read command takes --json
```

## 3. What we take from gianna, subsystem by subsystem

### LLM layer (`src/llm.rs`, `src/llm_providers/` in gianna)

- One `LlmProvider` trait; the load-bearing method is
  `chat_step(principal, system, history, tools) -> ChatStep`. Non-streaming.
- `FallbackLlm` wraps an ordered provider list: retryable errors get 3
  jittered-backoff retries on the same provider *before* falling through;
  context-overflow fails fast with no retry (the same prompt 400s everywhere).
  Wrap even a single provider for the retry behaviour.
- Tool schemas are provider-neutral `{name, description, parameters}` reshaped
  at the wire boundary per provider. Gianna shipped a real outage by leaking
  Anthropic's `input_schema` key to the OpenAI path — keep the reshaping.
- `FakeLlm` (deterministic, keyword-driven, no tools) and `ScriptedLlm`
  (queue-driven, scripts exact multi-step tool loops, panics if under-scripted)
  are both essential test doubles.
- Cost tracking: hand-maintained per-model price table with a deliberately
  expensive fallback price for unknown models; recorded fire-and-forget. Feeds
  `max_cost_per_day_cents`.

### Agent loop (`src/agent/`)

- Hand-rolled `for _ in 0..max_steps` tool loop (cap ~10–20) plus a separate
  wall-clock deadline. Tool errors never abort the turn — they return to the
  model as strings, split into user-facing (relayed with detail) vs internal
  fault (scrubbed, plus "do NOT retry" so the model doesn't burn steps on a
  dead backend). Duplicate-call guard on identical repeated action calls.
- System prompt ordered for provider prefix-cache: static persona → per-team /
  per-target context → volatile clock LAST.
- Memory is not pre-stuffed; the persona instructs the model to call
  `recall_memory`. Passive retention runs detached after each turn.
- Token-budgeted history replay (fold turns, collapse stale tool exchanges to
  one-line markers).
- Everything arriving from the outside world mid-diagnosis — webhook alert
  payloads, log lines, remote command output — is **data, not instructions**:
  framed as observations in context (gianna frames voice transcripts as
  reported speech for exactly this reason), never merged into the
  instruction stream. The framing is a mitigation; the policy choke point is
  the enforcement — a prompt-injected model still can't execute anything
  policy wouldn't allow it anyway.
- **Environment scepticism** is a standing prompt + eval requirement:
  corroborate, never trust a single signal — an app health endpoint may
  prove only that the process loop is alive (example's TinyHealthCheck
  checks no downstream connectivity), `df` lies under gVisor bind mounts
  (brief §9), and a green namespace is not an isolated environment when
  staging and prod share a cluster.
- **Difference from gianna:** gianna is act-then-announce because everything
  is reversible. OpsClaw is classify-then-gate: the policy layer decides
  execute / ask / block before anything runs. The loop shape survives; the
  dispatch inside it changes.

### Scheduler (`src/scheduler/`)

This is the heartbeat, and gianna's scheduler is almost exactly the brief's
§3.1 already:

- Supervised loops with panic-catch-respawn (one bad tick must not kill
  proactive behaviour until next deploy). Independent loops for anything
  slow (a long scan must never delay alert delivery — gianna's v0.6.4
  starvation regression).
- Phases wrapped so one failing phase never starves the others.
- The tick interval is **adaptive** (brief §3): a relaxed base cadence on
  healthy targets, tightened while an incident is active or a hypothesis is
  unconfirmed. Watchdog lag/stall thresholds derive from the current
  interval, not a constant.
- **Dead-man's switch = gianna's watchdog verbatim**: an atomic bumped at
  tick *start* (measures liveness, not success), with separate lag ("alive
  but slow") and stall ("dead") alerts, each rate-limited.
- **Anti-spam = gianna's claim table generalized**: atomically claim
  before composing/sending, keyed per (incident fingerprint, occurrence) —
  crash-safe exactly-once, dedup across ticks.
- `advance()` fast-forwards past missed occurrences (capped, self-healing)
  rather than replaying a backlog after downtime; exhausted one-shots retire
  themselves.
- Bounded compose concurrency (semaphore) + retry/backoff/dead-letter with a
  give-up window (gianna once re-ran a failed LLM compose every 60s
  indefinitely — ~1440 turns/day).
- Seeded scan jobs (one per project, at first boot) use gianna's
  prompt-from-const-at-fire-time pattern: seeded rows resolve their prompt
  from a code constant so improving the const upgrades every unedited job with
  no migration; a user-edited job converts to free text and keeps it forever.

### Persistence (`src/db/`)

- Trait-per-repo, `#[async_trait]`, SQLite impl (sqlx, runtime-checked
  queries so the crate builds with no live DB) + in-memory fake.
- **Parity suite**: one test body, a macro expands it against both backends;
  the real backend is the spec. Gianna adopted this after ~35% of trait
  methods were never exercised against the real DB and silently diverged.
- Boot-time auto-migration; applied migrations are immutable — every change
  is a new numbered file.
- Repos OpsClaw needs: incidents, approvals, audit, jobs, runbook_runs,
  memory bookkeeping, channel state, tokens. Targets/resources are NOT in the
  DB — config declares them (brief invariant #4); the DB holds runtime state.

### Memory (`src/memory/`)

- `Memory` trait; honest no-op when no backend is configured (`is_enabled()`
  lets tools tell the truth rather than fake a save).
- One bank per team. Attribution by framing: `"{operator} said: …"` /
  `"scan of {fq_target} observed: …"` — the shared-bank-with-attribution
  model is exactly gianna's household memory.
- `retain_detached`: background write with 3 retries + exponential backoff;
  a `TaskTracker` drains in-flight retains on SIGTERM so a deploy doesn't
  drop a just-learned fact. Reads inside the tool loop get a short (5s)
  timeout distinct from the write timeout.
- Upsert identity via a SHA-256 content hash (NOT Rust's `DefaultHasher`,
  which changes across toolchains) so corrections supersede duplicates.
- Cheap deterministic pre-retain filter (no LLM) so questions and noise never
  reach the store.
- Backend: **Hindsight**, as in gianna — port the client wholesale: one bank
  per team, `ensure_configured` with a domain-tuned retain/reflect mission
  and high literalism (applied once at boot; non-fatal but loudly logged on
  failure), raw text handed to the extractor (never pre-summarised), context
  + timestamp always supplied. Live mode refuses to boot without
  `HINDSIGHT_URL` (memory is a core promise — gianna's stance); fakes mode
  is the honest no-op. The standard install bundles a pinned Hindsight image
  via docker-compose (§5).
- Recall is hybrid keyword + semantic (brief §8) by Hindsight's own design:
  every recall runs semantic, BM25 keyword, graph, and temporal retrieval in
  parallel and rank-fuses them — no mode parameter exists or is needed.
- Retention/archival (brief §8): `memory.retention_days` declares the team's
  horizon (unset = keep forever). Hindsight exposes **no delete-by-age API**
  (its surface: retain / recall / list / reflect, per-fact invalidate,
  whole-bank delete), so the daemon does NOT silently prune — it warns at
  boot when the field is set, and enforcement is operator-driven:
  `opsclaw-cli memory export` (the human-readable archival dump — markdown
  with timestamp/context per fact, `--json` for the machine form, via the
  backend's complete `list` enumeration) plus per-fact `memory forget`.
  Deliberately honest: no fake deletion.

### Channels (`src/channels/`)

- Gianna's `Channel` trait nearly verbatim: only `name()` and `send()`
  mandatory; `listen()`, `can_reach()`, typing, self-message-drop default.
  `MultiChannel` fan-out; `RecordingChannel` for tests.
- Telegram is long-polling (persist the poll offset only after genuine
  hand-off — gianna documents the crash-window message-loss bug); the web
  channel is gianna's SSE hub with short-lived signed stream tickets. Slack
  is a later addition behind the same trait, not a launch channel.
- Web push (gianna's `push.rs` ported) is a send-only channel behind the
  same trait: incident alerts and approval requests deep-linking into the
  installed PWA's approval screen.
- Approval messages are just channel messages with structured context
  (command, fq target, risk class, hypothesis) + approve/deny actions —
  decidable from a phone (brief §5).

### HTTP gateway (`src/http/`)

- Axum; same layer-ordering discipline; graceful shutdown = drain HTTP, then
  bounded (~20s) budget for background work; document that the systemd/docker
  stop timeout must exceed the drain budget.
- Typed auth extractors that encode the permission in the handler signature
  (gianna's `AuthedRead`/`AuthedWrite` rationale: hand-rolled gate calls let
  a missing check ship silently).
- **Frontend model — a deliberate departure from gianna.** Gianna serves
  marketing and app from one server because gianna is one deployment.
  OpsClaw has one UI *per team*, so the split is: the operational web UI is
  embedded in the binary and served by each team's daemon (self-deploying,
  never publicly reachable, no UI/daemon version skew possible); marketing +
  docs + downloads live on **opsclaw.io, a separate purely-static site**
  with zero coupling to any daemon. No hosted console that reaches into
  team deployments — that's relay infrastructure and auth federation,
  explicitly out of scope for now.
- The web UI is embedded via `include_str!` (templated once at first
  request, `Cache-Control: no-cache` — gianna shipped a stale-app-shell
  incident).
  Day-one surfaces: agent chat (same orchestrator path as every channel, SSE
  for proactive push), incident list/detail with ack/resolve, the approval
  queue with approve/deny, status (heartbeat liveness, per-target scan
  state, e-stop), and config/target management. Config edits go through
  daemon API handlers that validate and rewrite `config.toml` — the file
  stays the single source of truth and stays hand-editable.
- Operator accounts are gianna's auth ported, with LOGIN made pluggable
  (`auth.provider`, §7 decision 16): `local` proves the operator with an
  argon2 password, `hanko` proves them with a passkey whose session token is
  verified server-side against the Hanko API. Only the front door changes.
  Under either provider the daemon mints and verifies its OWN HS256 JWT in an
  HttpOnly SameSite=Strict cookie with `token_version` revocation, no
  external token is ever accepted on an ordinary request, and the `accounts`
  row remains the principal on approvals and in the audit chain. The invite
  flow for teammates follows the configured provider.
- SSE auth uses short-lived signed stream tickets (never a long-lived token
  in a query string).
- The web UI is a **PWA on purpose**: web push is how incident alerts and
  approval requests reach operators' iOS/Android lock screens without a
  native app — and iOS only delivers push to a home-screen-installed PWA
  served over HTTPS. Gianna's push stack ports (`web-push-native`, VAPID);
  `onboard` generates the per-deployment VAPID keypair (gianna's
  `validate()` lesson: reject a half-set pair). Push is best-effort — iOS
  web apps get no critical-alerts tier — so the escalation chain never
  relies on it alone: Telegram and the outbound webhook (→ PagerDuty) are
  the guaranteed paths; push is the convenient one.
- Per-deployment PWAs work because web push needs **no Apple/Google
  registration**: VAPID is self-asserted, install is per-origin. Nuances:
  the notification arrives anywhere (it rides the vendors' push services;
  the daemon needs outbound HTTPS to those endpoints — bastion egress
  checklist), but tapping through to approve needs the phone to reach the
  daemon's origin; and the cert must be trusted by the *phone*, ruling out
  internal-CA certs in practice.
- Reaching the UI: VPN/tailnet or SSH tunnel (`opsclaw ui` opens tunnel +
  browser), like any internal ops UI (example reaches ArgoCD/Grafana behind
  the jumpbox). Because push needs a secure context with a
  publicly-trusted cert, the install guide treats **TLS as the norm**, with
  Tailscale on operators' phones as the golden path (trusted `ts.net`
  certs + phone-to-daemon reachability in one move); alternatives: Caddy
  with a public-DNS name via ACME DNS-01 — real certificates with no
  inbound exposure. Under `auth.provider = "hanko"` TLS stops being the norm
  and becomes **mandatory**: WebAuthn runs only in a secure context, so a
  passkey cannot be used over plain http off localhost.
- Webhook ingestion (Alertmanager, PagerDuty) → same orchestrator path as
  chat; HMAC/token verification with constant-time compare.

### Config (`src/config.rs`)

- Real-when-credential-set, **clearly-logged fake otherwise** — with zero
  config the whole daemon runs and self-validates on fakes. This is what
  makes the sim harness and e2e suite cheap.
- `validate()` fails hard before bind on dangerous misconfig, with special
  attention to values that fail open: gianna hard-fails a malformed spend cap
  because it would parse as "unlimited". OpsClaw equivalents: malformed
  `max_actions_per_hour`, an autonomy level that doesn't parse (must not
  default to anything but `observe`), a target with no credential ref.
- Targets and environments can declare `expected_state` (`running` /
  `stopped` / `ephemeral`): example's sandbox cluster is normally stopped
  (its API FQDN goes NXDOMAIN — a state, not an outage) and is wiped
  monthly. Intentional states must not page.
- Secrets are referenced by name in config (`env:VAR` or a key in the
  encrypted store) and resolved only at connect time; every resolved value
  is registered with the output scrubber (§4). `opsclaw_config` inventory
  output reports names/addresses/types/autonomy only, never values.
- Hand-written `Debug` redacting every secret to `<set>`/`<unset>`, with a
  test asserting no secret substring appears (serves brief invariant #3).

## 4. What's new — no gianna analog

### Policy choke point (`policy/`)

One function; every remote command passes through it; nothing else can reach
a `TargetExecutor`:

```
tool call → resolve fq target → risk-classify (code, not LLM)
  → e-stop check → autonomy gate (level + allow/deny lists + runbook match)
  → rate & cost caps → audit-begin → execute → audit-end
```

Outcomes: execute / queue approval / block-and-dry-run-log. Risk
classification is pattern-based over the concrete command plus the tool's
self-declared class — the tool trait carries `risk_class` metadata the same
way gianna's tools self-declare `is_action`/`allowed_in_job_run` (gianna
moved from central name-lists to self-declaration after silent gating bugs).

### Audit chain (`audit/`)

Append-only table: `{ts, principal, fq_target, tool, command, risk, outcome,
prev_hash, hash}`. Written by the policy layer on both sides of execution.
No bypass exists because the executor is only reachable through policy.
`opsclaw audit verify` re-walks the chain.

A **secret scrubber** sits on the same choke point: every secret value the
store can resolve is replaced with `<redacted:NAME>` in tool output, log
lines, and audit records before they are persisted or enter LLM context —
the runtime counterpart of config's `Debug` redaction (a remote `env` dump
must not leak a credential into the transcript). A test feeds a known secret
through each sink and asserts it never surfaces (definition-of-done #4).

### E-stop

Two mechanisms so it works when the daemon misbehaves: a sentinel file the
CLI writes directly (no daemon round-trip) + a DB flag; the policy choke
point re-reads the sentinel before every command. `estop resume` clears both.
Remote `estop` (PWA / remote CLI / chat) is a gateway endpoint; the hard
guarantee remains the local sentinel — SSH to the bastion works even when
the daemon is wedged. The brief's network-kill and domain-block modes are
later extensions of the same switch.

### External dead-man heartbeat

The internal watchdog (§3, scheduler) catches a stalled loop; nothing
internal can catch the whole daemon dying. Every tick, the daemon pings a
configured external receiver (a PagerDuty heartbeat, healthchecks.io, any
webhook outside the failure domain) so that silence itself pages. A standard
feature in every placement; mandatory for in-cluster installs.

### Approvals

Persisted `ApprovalRequest` rows carrying the full decision context. On
approve, the daemon executes the **stored command verbatim** — never a fresh
LLM interpretation of "yes, do it" — audited under both the agent principal
and the approving operator. Timeouts cancel via a scheduler sweep (the same
claim machinery). This satisfies definition-of-done #5.

### Incidents (`incidents/`)

Fingerprint = (fq target, fault class, resource). Lifecycle
`Active → Acknowledged → Resolved | Expired` as a deliberately coarse state
machine (gianna's 3-state billing lesson: coarse states + booleans beat
mirroring an external vocabulary). Escalation contact chain = scheduler jobs:
notify priority 0, claim, wait `ack_timeout`, escalate, re-notify on
`repeat_interval`. Resolution suppresses trailing alerts via the claim table.
Incidents are queryable (`opsclaw incidents`, PWA); `opsclaw postmortem <id>`
renders a structured postmortem from the incident's signals, hypothesis,
audit trail, and resolution.

### Runbooks (`runbooks/`)

Markdown files with TOML front matter: a trigger (alert categories, keywords,
target glob) and prose steps with `{placeholders}` (`{target}`,
`{container}`, `{service}`, `{namespace}`). A runbook match is the
pre-approval that unlocks `act_on_known` in the policy gate — the mechanism
by which human knowledge becomes bounded automation. Per-step failure
handling (abort / continue / retry), full execution history, per-runbook
success-rate tracking with low scorers surfaced for review. CLI:
`runbook init/list/show/run --target ... --var k=v` (brief §7).

### Targets & executors (`targets/`)

`TargetExecutor` per target type (ssh / local / kubernetes / cloud) —
connect with a named credential, run a command, stream output, classify exit.
Tools compose on executors; the fq target path is resolved and authorized by
the dispatcher, never trusted from model output (gianna's DATA boundary:
tenancy ids are positional trusted arguments, never model-supplied).

The ssh executor supports jump hosts (example's estate sits behind an Azure
Bastion jumpbox). One physical system may back two environments — example's
staging and prod are namespaces on one AKS cluster — modelled as **two
Targets with distinct namespace-scoped credentials** (separate
ServiceAccount kubeconfigs): invariant #1 (one target = one credential set =
one audit identity) is preserved by credential scoping, and environment
isolation is exactly as real as that scoping makes it. Each Kubernetes target
also declares its context and either one namespace or explicit cluster scope;
the tool and executor enforce that boundary before the API server's RBAC gets
a second chance to refuse it. Keep the `cloud`
target type provider-pluggable — example has a Scaleway migration plan on
file; Azure must be a provider, not the architecture.

### Tool surface (`tools/`)

The fork's tool list (brief §10) is the inventory; its topical grouping
(diagnostic / observability / provider) is documentation, not architecture.
The load-bearing division is **what backs the tool**:

1. **Executor-backed** — tools that compose a concrete command and run it
   through the policy choke point → `TargetExecutor`. `ssh` (raw command
   runner), `shell` (the daemon host as the `local` target), `monitor`
   (cpu/mem/disk/proc), `systemd`, `docker`, `firewall`, and `kubernetes`'s
   exec paths. These tools own *vocabulary*, never transport — the fork's
   rule "every remote command goes through the auditing SSH runner
   regardless of which tool issued it" generalizes to: **no tool owns a
   connection; there is one execution path per target type, and audit and
   policy live there.**
2. **Endpoint-backed** — protocol/HTTP clients against declared Resources
   with named credentials: `prometheus`, `loki`, `elasticsearch`, `jaeger`,
   `eventstore`, `argocd`, `sentry`, `postgres`, `rabbitmq`,
   `azure_service_bus`, `cloudflare`, `github`, `pagerduty`, `posthog`,
   plus the `kubernetes` API side. Same choke
   point — a `DROP TABLE` over a postgres client is as classified, gated,
   and audited as an ssh command. `dns`/`cert` sit here too but accept an
   optional target (resolve/check from a target's vantage or the daemon's).
3. **Daemon-local** — no remote side effect: the structured `notify` tool
   (exactly one — the `escalate_to_human` / `opsclaw_notify` split was a
   fork scar), `opsclaw_config` (read-only, secret-free inventory),
   memory store/recall/forget, incident + runbook queries, workspace-bounded
   file read/write, web search/fetch.

Registration rules kept from the fork, implemented via gianna's self-declared
capability metadata (never central name-lists): read-only tools register
whenever their config section exists; **mutating tools register only when a
matching target/resource is configured**; heartbeat/background runs get a
deny-by-default subset (gianna's `allowed_in_job_run`). Each tool declares a
coarse risk class; command-composing tools get pattern-based per-command
classification on top.

Cleanups vs the old list: `kubernetes` is one tool (the brief's `kube` split
is an artifact); zeroclaw's `cron_*` is subsumed by scan-job management tools
over the scheduler (gianna's routines pattern); `git_operations` is dropped
(GitHub tool + ssh cover it); `a2a` stays out per brief §12. `elk` is
renamed `elasticsearch` for what it actually talks to.

v1 ships the executor-backed set + `kubernetes` +
notify/config/memory/generic, plus the endpoint-backed tools the reference
deployment (example — see `docs/REFERENCE.md`) actually needs:
`elasticsearch` (read models *and* logs — example ships logs via Filebeat
into ES, so log search is an ES query and `loki` stays a stub),
`azure_service_bus` (DLQ depth/peek is daily on-call work), `eventstore`
(KurrentDB — example's system of record; two of its nine real postmortems),
`prometheus`, and `argocd` (sync status read-only; rollback as a gated
mutation — in a GitOps shop remediation is a revert/rollback, not `kubectl
apply`). The remaining provider tools stay stubs behind the trait until
asked for.

## 5. Installation & operator experience

Installed product, not SaaS. The **standard install is a docker-compose
file**: the opsclaw image (glibc-pinned two-stage build — gianna pins builder
and runtime to the same Debian release) plus a **pinned** Hindsight image
(gianna's lockstep-pinning rule: never bump it casually). A bare-binary
install (`cargo install` / prebuilt release) is supported but must point
`HINDSIGHT_URL` at an existing instance.
`opsclaw onboard` → `config project add` (chaining wizards) → `doctor` →
`daemon` in under ten minutes is definition-of-done #1. Ship a
`systemd` unit example; document that `TimeoutStopSec` must exceed the drain
budget. No auto-update; versioned releases, immutable tags.

**Placement**: the daemon is location-agnostic; the recommended placement is
*adjacent* to what it watches — a bastion/ops host or a managed container
service — never inside the monitored failure domain, so it can report a dead
cluster and stay reachable mid-incident. Clusters are always targets reached
via kubeconfig (bound to a dedicated least-privilege ServiceAccount),
wherever the daemon runs, so no cluster is "special". **In-cluster is a
supported packaging**: a Helm chart — single replica, SQLite on a PV,
priority class + PodDisruptionBudget so opsclaw is among the last pods
evicted — with the correlated-failure caveat documented and the external
dead-man heartbeat (§4) required in that shape.

## 6. Testing

Gianna's core insight ports directly: **production and tests share one wiring
path** — `AppState::new(Config::default())` is a fully-faked daemon, no
separate mock layer to drift.

- **Tier 1**: per-tool integration tests; parity suite for repos; `wiremock`
  for HTTP-backed tools; `ScriptedLlm` for exact tool-loop scripting.
- **Tier 2 (the acceptance test, brief §9)**: full daemon vs a
  gVisor-sandboxed target; scenarios as directories with
  `arm.sh`/`disarm.sh`/`expected.json`; assert detection, correct naming,
  one structured notify, no spam; a silent-baseline scenario asserts silence
  on health. Run the daemon with a **scrubbed, non-inherited environment** so
  an ambient real credential can never flip the daemon live mid-test
  (gianna's web-tests lesson). Port the currently-failing scenarios as
  requirements: 4-way CPU saturation, log-file growth, restart-flapping
  cadence, and mount-scepticism (evaluate writable mounts, not every mount).
- **The harness must be unable to harm the host — a hard requirement, not a
  nicety.** A fault-injection scenario deliberately creates the fault it
  tests, so its blast radius must be bounded to the sandbox by construction:
  (a) every resource a scenario can exhaust is **capped inside the sandbox**:
  disk via size-capped mounts (`--tmpfs /data:size=200m`), never the
  container's writable layer — otherwise `df` inside an overlay container
  reports the *host* filesystem and a "fill 90% of the disk" fault fills 90%
  of the host (not hypothetical: an un-capped `/data` wedged the dev machine
  at 100% during this build) — and memory/CPU via `--memory`/`--cpus`, the
  same escape by another door: a percentage-based stressor sizes itself off
  `/proc/meminfo`, and an unlimited container sees the host's RAM (observed
  as a ~50GB attempted allocation before the cap landed); (b) scenario containers are **force-reaped on every
  exit path** — normal, failure, and signal (a Ctrl-C'd parallel run is
  exactly how a ballooned container survives to hoard host disk); (c)
  fill-style scenarios carry an absolute ceiling and refuse rather than
  allocate a fraction of an implausibly large "available" figure. The rule:
  a scenario that escapes its sandbox is a harness bug of the same severity
  as a missed detection.
- **Tier 2, kubernetes**: scenarios run against a throwaway **k3d** cluster —
  opsclaw on the host with the k3d kubeconfig as its `kubernetes` target,
  i.e. the bastion-adjacent production shape in miniature. Fault classes:
  CrashLoopBackOff, evictions/node pressure, failed rollouts, and
  whole-cluster death (kill k3d; assert opsclaw escalates "cluster
  unreachable" — untestable if the agent lived inside it). One smoke
  scenario installs the Helm chart in-cluster to keep that packaging honest.
- **Tier 3**: e2e in-process daemon on fakes — onboard, lifecycle, doctor,
  estop; real HTTP against a real bound server (gianna's `e2e_flow`).
- **Live eval tier**: env-var-gated (self-skip, never `#[ignore]`), run
  against the *shipped* model ("an eval against a different model than
  production ships is a comfortable lie"), scheduled not per-PR, and
  release-gated: the release recipe refuses to tag unless the last scheduled
  eval run is green.

## 7. Decisions taken (revisit only with cause)

1. **One shared daemon per team** is the team model; shared memory, incidents
   and approvals derive from it. No memory-sync protocol.
2. **SQLite default** for the daemon's own store (brief §8); repo traits +
   parity suite keep Postgres a backend, not a rewrite. Memory itself lives
   in Hindsight (below), not the relational store.
3. **Four-level autonomy vocabulary** only (`observe / suggest /
   act_on_known / auto`); `suggest` is the default; unparseable → `observe`.
4. **Risk classification in code** drives gating; the LLM never decides its
   own permissions.
5. **Channels at launch: web UI (installable PWA with web push) + Telegram
   + CLI**, plus outbound webhook for escalation delivery. Push is
   best-effort by design; Telegram/webhook are the guaranteed escalation
   paths. Slack comes later behind the same trait.
6. **Memory backend: Hindsight**, bundled in the standard docker-compose
   install with a pinned image; live mode refuses to boot without it.
7. **Targets in v1: ssh + local + kubernetes + cloud (azure).** Endpoint
   tools in v1: `elasticsearch`, `azure_service_bus`, `eventstore`
   (KurrentDB), `prometheus`, `argocd`; other provider tools (postgres,
   cloudflare, github, loki, ...) remain trait stubs. Rationale:
   `docs/REFERENCE.md`.
8. **Web-UI auth: gianna-style accounts** (argon2 + JWT + invites) — now the
   `local` provider (decision 16); the operator roster lives in the DB and is
   the principal for approvals/audit under every provider.
9. **Web-UI scope day-one: all four surfaces** — chat, incidents +
   approvals, status dashboard, config/target management (config.toml stays
   canonical).
10. **No vertical slices** — the whole system is built in one campaign, but
    a detailed implementation plan (module order, interfaces, test matrix)
    is written and reviewed before any build starts.
11. **Two frontends.** The operational web UI is embedded in the daemon
    binary, one per team, internal-only; opsclaw.io is a separate static
    marketing/docs/downloads site. No hosted console into deployments.
12. **Placement: adjacent by default, in-cluster supported.** The reference
    deployment is example (`~/src/example` — k8s + Azure + Elasticsearch),
    where opsclaw runs on their existing bastion; the Helm chart exists for
    teams that want in-cluster, where the external heartbeat is mandatory.
13. **Shipped LLM default: OpenRouter only** — one provider with its
    server-side ordered model list, wrapped in `FallbackLlm` for
    retry/backoff (gianna's production shape; `validate()` requires
    `OPENROUTER_MODELS` when the key is set). Live evals run against this
    exact chain. The Anthropic/OpenAI provider impls still ship —
    provider-agnostic per the brief — they're just not the default.
14. **Remote CLI v1: small set** — chat, incidents, approve/deny, estop,
    status over the token-auth gateway; everything else is local CLI or
    web UI.
15. **Repo posture: proprietary for now** — no LICENSE file until a
    deliberate decision before anything is published.
16. **Auth provider is a config choice** — `auth.provider = "local"` (argon2
    passwords, decision 8) or `"hanko"` (passkeys, each sign-in verified
    server-side against the Hanko API). It changes the front door only: the
    daemon mints and verifies its own HS256 cookie either way, `Authed` and
    the `ops_` CLI bearer are untouched, and an identity Hanko authenticates
    but no `accounts` row claims is refused — no auto-provisioning. Choosing
    hanko makes TLS mandatory rather than merely normal, because WebAuthn
    needs a secure context.
