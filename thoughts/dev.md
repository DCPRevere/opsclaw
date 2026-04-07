# Dev

How to turn the ZeroClaw fork into OpsClaw.

**Last updated: 2026-03-18**

## What ZeroClaw already gives us

- Trait-driven plugin architecture (Provider, Tool, Channel, Memory, Sandbox, Observer)
- Cron scheduler with cron expressions, fixed intervals, one-shots, per-job tool allowlists
- Daemon mode with supervised components (gateway, channels, scheduler, heartbeat)
- 13 LLM providers, 25+ channel adapters (Telegram, Slack, Email already work)
- Security policy engine with autonomy levels, credential scrubbing, sandbox backends
- Prometheus and OpenTelemetry observability
- SQLite memory backend with keyword search
- Single binary, low footprint, runs on a cheap VPS
- **SecretStore** — ChaCha20-Poly1305 encrypted credentials in config, transparent decrypt at load time
- **Merkle hash-chain audit trail** (upstream v0.4.3) — tamper-evident append-only logging
- **Knowledge graph** for expertise capture (upstream v0.4.3)
- **Reddit, Bluesky, Webhook channel adapters** (upstream v0.4.3)

### Key principle: leverage upstream

ZeroClaw already solves many infrastructure problems (credentials, audit, channels, scheduling). **Don't duplicate or replace what upstream provides.** If ZeroClaw has a good solution, use it. Only build what's genuinely new to OpsClaw (target monitoring, SSH scanning, K8s, probes, baselines).

### Key principle: passive observer — no changes to existing infrastructure

OpsClaw should fit into existing infrastructure without requiring anything to change. Monitored services don't need to be modified, instrumented, or reconfigured. OpsClaw is a read-only consumer: it queries APIs that already exist, SSHes in with read-only access, and tails logs that are already being written.

This means:
- **No OTLP push receivers** — don't require services to push telemetry to OpsClaw. Instead, query existing OTEL backends (Jaeger, Tempo, Grafana) via their APIs.
- **No agents on targets** — no sidecar processes, no log shippers, no exporters installed on the monitored box.
- **No CI/CD webhooks** — don't require pipelines to call OpsClaw. Instead, poll GitHub/GitLab APIs for releases, tags, and workflow runs.
- **Data sources are credentials, not integrations** — to add a new signal, the user provides an API token. Nothing else changes.

Existing telemetry backends (Seq, Jaeger, Prometheus, Grafana) are data sources OpsClaw queries during diagnosis. OTEL's existing `OtelObserver` (in `src/observability/`) is for emitting OpsClaw's *own* telemetry — not for receiving data from monitored services.

### Key principle: replace the engineer, not the dashboard

OpsClaw is not a monitoring tool. Datadog, Grafana, PagerDuty — those are dashboards and alerts. They tell you something's wrong. OpsClaw **acts**. It SSHes in, reads logs, diagnoses with LLM reasoning, executes runbooks, and escalates with full context. The goal is to replace $100k+ of DevOps salary, not to be another graph.

Target market: solo founders (can't afford DevOps) → growing startups (overwhelmed DevOps) → mid-size companies (replace L1 on-call). See `thoughts/vision.md` for full positioning.

## What we build

Phases are ordered by dependency — each one builds on the last. The goal is a working end-to-end MVP (setup → scan → monitor → alert) as fast as possible.

### Phase 1: MVP — setup, scan, monitor, alert ✅ COMPLETE

Everything needed for a user to run `opsclaw setup`, point it at a server, and get alerts when something looks wrong.

**Status (2026-03-17):** All Phase 1 components built and merged to master. Binary compiles as `opsclaw` (21MB release). End-to-end flow wired: config → SSH → scan → health diff → LLM diagnosis → Telegram alert. Needs integration testing against a real target (Sacra on Hetzner).

#### 1a. Target config schema

Extend ZeroClaw's config with a `[[targets]]` section. Parsing, validation, loading.

```toml
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
user = "opsclaw"
key = "/etc/opsclaw/keys/prod-web-1"
autonomy = "observe"
context_file = "context/prod-web-1.md"

[[targets]]
name = "this-box"
type = "local"
autonomy = "observe"
context_file = "context/this-box.md"
```

Two target types for MVP: `ssh` and `local` (sidecar). Each gets its own autonomy level and freeform context file.

#### 1b. Secret store

Needed before anything else touches credentials. SSH keys, notification tokens, DB passwords — all go through here.

`opsclaw secret set` encrypts and stores credentials locally. Config references secrets by name, never by value. Resolved at runtime.

```
opsclaw secret set slack-webhook
> URL: https://hooks.slack.com/services/...
```

Storage: encrypted file on disk. Same approach on VPS, Docker, or Kubernetes. Users can optionally integrate with Vault or cloud KMS, but the default is self-contained.

Depends on: nothing. Build this first.

#### 1c. SshTool

Implement the `Tool` trait. Uses `russh` or `async-ssh2-lite` for async SSH.

Parameters: target name (resolved from config), command to run. Returns stdout, stderr, exit code.

The tool must:
- Resolve the target from config (host, user, key path)
- Resolve SSH key from the secret store
- Never expose the SSH key contents to the LLM
- Respect autonomy level — some commands are read-only (allowed at observe), some are writes (require higher levels)
- Log every command to the audit trail
- Enforce a configurable timeout per command
- Support both interactive (allocate PTY) and batch modes

Depends on: 1a (target config), 1b (secret store).

#### 1d. Discovery scan

A built-in routine, not a tool the LLM calls directly. Runs on first connect and on demand.

Uses SshTool (or local commands in sidecar mode) to run read-only commands:
- `ps aux`, `ss -tlnp` — processes and ports
- `docker ps`, `docker inspect` — containers
- `systemctl list-units` — systemd services
- `journalctl --list-boots` — log availability
- `df -h`, `lsblk` — disk
- `cat /etc/os-release` — OS info
- Scan `/var/log` for known log files
- Check for Postgres, MySQL, Redis on standard and non-standard ports

Produces a structured target snapshot stored in memory. The user reviews and corrects it.

Depends on: 1c (SshTool).

#### 1e. Notification channel setup

ZeroClaw already has channel adapters for Telegram, Slack, Discord, Email, webhook. What's missing is the guided CLI setup: "here's how to create a Telegram bot, paste the token here."

The setup flow walks the user through getting credentials for their chosen channels and stores them via the secret store. Multiple channels supported with different roles (e.g. email for digests, Slack for urgent alerts).

Depends on: 1b (secret store). Uses existing ZeroClaw channel code.

#### 1f. Basic monitoring loop

A periodic sweep using ZeroClaw's existing scheduler. Each check is a cron job of type `Agent` with:
- A system prompt that includes the target's snapshot and context
- `allowed_tools` restricted to `ssh` (or local) plus `memory_recall`, `memory_store`
- `session_target = "Isolated"` so checks don't pollute each other
- A delivery config pointing to the notification channel

"Every 5 minutes, SSH in, check containers are running, compare against snapshot, alert if something's wrong."

This is the minimum viable monitoring. It's a periodic sweep only — no event streams, no log tailing, no baseline learning yet.

Depends on: 1c (SshTool), 1d (scan snapshot to compare against), 1e (somewhere to send alerts).

#### 1g. `opsclaw setup` CLI

The glue. An interactive terminal session that ties 1a–1f together:

1. Where am I running? (same box / remote)
2. If remote: collect SSH details, test connection, store key
3. Run discovery scan, show results, user confirms or corrects
4. User adds target context for anything the scan can't infer
5. Choose autonomy level
6. Set up notification channels
7. Configure check interval
8. Write config file, start monitoring

Extends ZeroClaw's existing `onboard` command (which handles provider/model setup). `opsclaw setup` adds the target, scan, context, autonomy, and notification steps.

Depends on: everything above.

#### MVP build order

```
1b secret store
     ↓
1a target config ──→ 1c SshTool ──→ 1d discovery scan
                                         ↓
1e notification setup ──────────→ 1f basic monitoring loop
                                         ↓
                                  1g opsclaw setup CLI
```

At the end of Phase 1, a user can: install OpsClaw, run `opsclaw setup`, point it at their server, see what's running, get alerts on Slack/Telegram/email when something changes or goes down. Observe mode only.

### Phase 2: Deeper monitoring and Kubernetes 🔨 IN PROGRESS

Build on the MVP with richer monitoring and a new target type.

**Status (2026-03-17):** Event streaming done. K8s discovery, log sources, external probes, and baseline learning all being written by parallel agents. Upstream merged to v0.4.3 (76 commits, including Merkle audit trail).

#### Event stream (real-time)

Subscribe to continuous event sources:
- **Docker:** `docker events` stream for container state changes
- **systemd:** `journalctl -f` for service failures

Catches things the moment they happen, instead of waiting for the next periodic sweep.

#### Log sources

Add support for reading logs from multiple sources:

- **Docker** — `docker logs` via the Docker socket (real-time)
- **systemd** — `journalctl` over SSH
- **Files** — tail `/var/log/whatever` over SSH
- **External log stores** — Elasticsearch, Loki, CloudWatch, etc. via API

External stores are often the better source — more history, structured fields, cross-service search. If the user has Filebeat shipping to Elasticsearch, OpsClaw should use that as primary and fall back to container/file logs for real-time tailing.

Credentials for external log stores go through the secret store.

#### KubeTool

Implement the `Tool` trait. Uses `kube-rs` for async Kubernetes API access.

OpsClaw runs as a pod with a ServiceAccount. Permissions granted via RBAC — read-only ClusterRole for observe mode, expanded for higher autonomy levels.

Capabilities by autonomy level:
- **Observe:** get/list/watch pods, services, events, nodes, configmaps, deployments, replicasets, statefulsets, daemonsets. Read pod logs.
- **Suggest:** same, but can propose actions for user approval.
- **Act on known:** exec into pods, restart deployments, scale replicas — matched runbook actions only.
- **Full auto:** all of the above plus novel remediation.

The user creates RBAC resources themselves — OpsClaw walks them through it during onboarding but can't bootstrap its own permissions.

Adds a `kubernetes` target type, Kubernetes discovery scan, and Kubernetes event stream.

#### External probes

Are your endpoints actually reachable from outside? Health endpoint probes, TLS certificate checks, DNS resolution. May need to run from a different location than the target.

#### Baseline learning

Extend the memory backend to store time-series observations:
- CPU, memory, disk usage at each check
- Request rates, error rates, response times (if the app exposes them)
- Container restart counts
- Postgres connection counts, replication lag

The LLM doesn't process raw time-series. A lightweight stats module computes rolling averages and standard deviations. The LLM sees: "CPU is at 85%, normally 40% ± 5% at this time of day" — enough to reason about.

### Phase 3: Diagnosis and remediation

#### Incident memory

A new memory category (`MemoryCategory::Incident`) with structured fields:
- Timestamp
- Target
- Symptoms (what was observed)
- Diagnosis (what the LLM concluded)
- Actions taken
- Outcome (resolved, escalated, unresolved)
- Resolution notes

When the LLM diagnoses a new issue, it searches incident memory first: "have I seen this before?" If yes, skip straight to the known fix (if autonomy allows).

#### Runbooks

Executable remediation procedures. Start with a hybrid format: structured steps with freeform annotations. The LLM can both follow and update them when it discovers a better approach. "Living runbooks."

Runbook execution respects autonomy levels. At "suggest," present steps and wait for approval. At "act on known," run them and report after. At "full auto," also create new runbooks from novel fixes.

#### Autonomy enforcement

Three user-facing modes that map to the underlying security levels:

##### Dry Run ("show me what you'd do")
- Records all actions OpsClaw *would* have taken, without executing them
- Outputs to audit log: `WOULD_HAVE: docker restart sacra-api`
- Read-only commands (scans, health checks, log reads) still execute normally
- Write commands are intercepted at the `CommandRunner` level and logged instead
- Config: `autonomy = "dry-run"` per target
- **Purpose:** evaluation period for new deployments, compliance audit, building trust

##### Approval Mode ("ask me first") — default for new targets
- Every destructive action requires explicit user approval before execution
- Flow: diagnose → propose action → send approval request via notification channel
- User approves/rejects via Telegram inline button, Slack reaction, or reply
- Timeout: if no response in N minutes, escalate to secondary contact or skip
- Approved actions execute immediately and log the approval + result
- Config: `autonomy = "approve"` per target
- Uses ZeroClaw's existing inline button support on Telegram

##### Auto Mode ("YOLO") — opt-in only
- Full auto remediation. OpsClaw diagnoses and fixes without asking.
- Still logs every action to the append-only audit trail (non-negotiable)
- Config: `autonomy = "auto"` per target
- Requires explicit opt-in — never the default
- Recommended only after an evaluation period in dry-run or approval mode

##### Mapping to existing ZeroClaw levels

| User-facing mode | SecurityPolicy.autonomy | Behaviour |
|---|---|---|
| dry-run | Conservative | Read-only executes; writes logged but not run |
| approve | Interactive | All commands allowed, writes need approval |
| auto | Autonomous | All commands, no approval gate |

`SshCommandRunner` already has `is_read_only_command()` enforcement — dry-run mode extends this by intercepting *all* non-read commands rather than blocking them.

Per-target and per-action-category overrides supported.

### Phase 4: External data sources

**Goal:** enrich diagnosis with signals from existing infrastructure — telemetry backends, CI/CD, and structured log stores — without requiring any changes to monitored systems.

When the LLM diagnoses an incident, it currently sees: current system state (from SSH/Docker), log excerpts, and past incident memory. Phase 4 adds a structured `DataSource` trait that OpsClaw can query during diagnosis to pull in correlated context.

#### Design

```rust
pub trait DataSource: Send + Sync {
    fn name(&self) -> &str;
    /// Fetch recent context relevant to a target/time window.
    async fn fetch_context(&self, target: &str, window: TimeWindow) -> Result<DataContext>;
}
```

Multiple sources are queried in parallel when diagnosis starts. Each produces a `DataContext` — structured text + metadata — that gets appended to the LLM's diagnosis prompt: "here's what Seq logged in the last 10 minutes, here's the last deployment, here's the Jaeger trace for the failing endpoint."

#### Data sources: telemetry backends

These are likely already running; OpsClaw just needs an API token.

- **Seq** — already in Sacra stack (port 33200). Query via `GET /api/events?count=N&filter=@Level='Error'&apiKey=...`. Good for structured error correlation: "were there error-level events in the 5 minutes before the alert?"
- **Jaeger** — already in Sacra stack (port 33300). Query recent traces via `GET /api/traces?service=X&limit=N`. Good for latency spikes and dependency failures.
- **Prometheus/Grafana** — PromQL API (`/api/v1/query_range`). Good for metric anomalies during the incident window.
- **Elasticsearch/OpenSearch** — query via REST API. Alternative to Seq for structured logs.

All read-only. No configuration changes on the monitored side.

#### Data sources: CI/CD and deployment history

Correlating incidents with deployments is one of the highest-value diagnosis signals. "Did anything deploy in the last 2 hours?"

- **GitHub API** — poll `/repos/{owner}/{repo}/releases`, `/deployments`, `/actions/runs`. Read-only, needs a GitHub PAT with `repo` scope. Supports filtering by time window.
- **GitLab CI API** — similar endpoint shape.
- **Docker image timestamps** — lower-effort alternative: SSH in and run `docker inspect {container} --format '{{.Created}}'` to get when the currently running image was pulled/started. Cross-reference against GitHub to find the matching commit. Zero config beyond existing SSH access.

The Docker inspect approach is particularly valuable for Sacra-style stacks: no CI integration needed, OpsClaw can determine "this container image changed 47 minutes ago" by itself.

#### First targets

Given Sacra's current stack on Hetzner:

1. **Seq source** — query error logs for the incident time window. API key already known.
2. **Jaeger source** — query failing service traces. Port already open.
3. **GitHub source** — poll `remundo-xml/Remundo.Ui.Platform` and `dcprevere/sacra` for recent deploys. Needs a PAT.
4. **Docker deploy timestamp** — via existing SSH runner, no additional config.

These four together give OpsClaw a much richer diagnosis context than SSH + logs alone. The LLM can reason: "sacra-api crashed at 02:17, a new image was deployed at 02:05 (based on docker inspect + GitHub), and Seq shows NullReferenceException errors starting at 02:06."

#### Config shape

```toml
[[targets.data_sources]]
type = "seq"
url = "http://localhost:33200"
api_key_secret = "seq-api-key"

[[targets.data_sources]]
type = "jaeger"
url = "http://localhost:33300"

[[data_sources]]
type = "github"
token_secret = "github-pat"
repos = ["remundo-xml/Remundo.Ui.Platform", "dcprevere/sacra"]
```

### Phase 5: Escalation and reporting

#### Escalation engine

When OpsClaw can't fix something or autonomy doesn't allow it:
1. Package the diagnosis: what happened, what was checked, what was tried, what the likely cause is
2. Send to the primary on-call via the configured channel
3. Wait N minutes for acknowledgement
4. If no response, escalate to secondary
5. Keep retrying with increasing urgency

State machine layered on top of ZeroClaw's channel system.

#### Digests and reports

Periodic summaries: "In the last 24 hours: 3 health checks found anomalies, 1 was auto-resolved (container restart), 2 are being monitored. Disk usage on prod-web-1 is trending up — 78% now, projected full in 12 days."

Delivered via the configured channel on a schedule (daily digest, weekly summary).

### Phase 6: Polish

- Rename all ZeroClaw references to OpsClaw (binary name, config paths, docs)
- Strip the README and docs back to OpsClaw's scope
- Web dashboard for incident history and audit log (ZeroClaw's gateway gives us the API layer)
- Database diagnostic tools (Postgres read-only queries via a new `DatabaseTool`)

## Resolved decisions

- **Upstream tracking:** Track upstream, merge regularly. First merge done (v0.4.3, 76 commits). Hard-fork only if/when divergence becomes unmanageable.
- **Testing:** MockCommandRunner + integration tests with canned output. 6 pipeline tests passing. Real SSH testing against Sacra (Hetzner) planned.
- **Secret store:** Use ZeroClaw's existing `SecretStore` + `decrypt_optional_secret()` pattern. `OpsClawSecretStore` is likely redundant — review and consider removing. Keep `opsclaw secret` CLI as UX convenience if needed but route through upstream infrastructure.
- **Credential management:** ZeroClaw already handles encrypted credentials for all config fields (Telegram bot tokens, Slack tokens, API keys, DB URLs). No new infrastructure needed — just wire OpsClaw's `NotificationConfig` and `TargetConfig` fields into the existing decrypt pipeline.

## Open questions

- Rust contribution barrier: is this a problem for the project? Most SRE/DevOps people know Python or Go, not Rust.
- External probes: where do they run? If OpsClaw is inside the cluster, it can't check external reachability from outside. Needs a separate probe, or a second OpsClaw instance, or a lightweight external ping service.
- Secret store encryption key: where does the master key live? If it's on disk next to the encrypted store, it's security theatre. Options: derive from a passphrase at startup, use a hardware key, use cloud KMS.
- Approval flow UX: how does the Telegram inline button flow work for approval mode? ZeroClaw has the button infrastructure — need to design the specific interaction pattern for "OpsClaw wants to restart container X, approve?"
