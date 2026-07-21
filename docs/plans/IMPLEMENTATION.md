# OpsClaw — Implementation Plan

**Status: draft, awaiting sign-off. Nothing here is built.**

Inputs: `OPSCLAW_BRIEF.md` (intent), `docs/DESIGN.md` (architecture),
`docs/REMUNDO.md` (reference deployment), `~/src/dcprevere/gianna.chat`
(parts donor). This plan adds the *how*: ground rules, frozen contracts,
the port inventory, build order, and the test matrix.

## 0. Ground rules

1. **Transplant, don't fork.** Gianna code is copied in, renamed, and owned.
   No upstream tracking, ever — that was the zeroclaw mistake.
2. **Two-commit porting.** Port verbatim (rename-only) in one commit, adapt
   in the next. Regressions stay attributable: did we break it, or did
   gianna never do it?
3. **Safety before brain.** No commit may exist in which the agent loop can
   reach a `TargetExecutor` except through `policy/` + `audit/`. The safety
   core (Wave 2) lands before the agent loop is wired to real tools.
4. **Fakes spine first.** From Wave 0 on, `Config::default()` boots a
   fully-faked daemon; every later module lands with its tests running
   against that spine. This is gianna's single most valuable property.
5. **Discipline day one.** `AGENTS.md` adapted from gianna's at repo
   creation (immutable migrations, parity-before-merge, verification beats
   confidence, minimal docs); eval-gated `just release` wired before there
   is anything to release.

## 1. Frozen contracts

Hand-written in Wave 0, before any parallel fan-out. Changing one afterwards
is a main-session decision, not something a module agent does unilaterally.
Signatures below are sketches; exact argument lists are settled in the
Wave 0 PR.

```rust
// domain/ — pure types
struct FqTarget { project, env, target, resource: Option<(ResourceType, String)> }
enum TargetKind   { Ssh, Local, Kubernetes, Cloud(CloudProvider) }
enum Autonomy     { Observe, Suggest, ActOnKnown, Auto }   // unknown string = config error, never a default
enum RiskClass    { Read, Medium, High, Destructive }
enum IncidentState{ Active, Acknowledged, Resolved, Expired }
enum ExpectedState{ Running, Stopped, Ephemeral }
enum Principal    { Agent { job: Option<JobId> }, Operator(AccountId), System }

trait LlmProvider {
    async fn chat_step(&self, p: &Principal, system: &str,
                       history: &[Turn], tools: &[ToolSpec]) -> Result<ChatStep>;
}

trait Tool {
    fn name(&self) -> &'static str;
    fn description(&self) -> &str;
    fn schema(&self) -> serde_json::Value;          // hand-written JSON Schema
    fn risk(&self) -> RiskClass;                    // coarse; command tools refined by the classifier
    fn is_action(&self) -> bool;
    fn allowed_in_heartbeat(&self) -> bool;         // deny-by-default subset for background runs
    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult>;
}
// ToolCtx carries the principal and a handle to policy::execute — tools can
// NEVER hold an executor. This is the no-bypass invariant expressed in types.

trait TargetExecutor {
    async fn run(&self, cmd: &Command, timeout: Duration) -> Result<ExecOutput>;
    async fn probe(&self) -> Result<ProbeReport>;   // doctor/connectivity
}

// policy/ — the choke point; the ONLY caller of TargetExecutor::run
async fn policy::execute(req: CommandRequest) -> PolicyOutcome;
enum PolicyOutcome { Executed(ExecOutput), NeedsApproval(ApprovalId),
                     Blocked { reason, dry_run_logged: bool }, EStopped }

trait Channel { /* gianna verbatim: name+send mandatory, rest defaulted */ }
trait Memory  { /* gianna verbatim: is_enabled, retain_detached, recall,
                  reflect, list, invalidate, drain_detached, health */ }
```

Repos (trait-per-repo, gianna pattern): `IncidentRepo`, `ApprovalRepo`,
`AuditRepo`, `JobRepo`, `RunbookRunRepo`, `AccountRepo`, `TokenRepo`,
`ChannelStateRepo`, `ControlRepo`.

## 2. Port inventory (gianna → opsclaw)

**Verbatim tier** (port with tests, rename-only first commit):

| gianna | opsclaw | notes |
|---|---|---|
| `src/llm.rs`, `src/llm_providers/{anthropic,openai_compat,fallback}.rs` | `llm/` | drop the Intent/classify fallback path — opsclaw has no tool-less production mode; keep `FakeLlm` + `ScriptedLlm` |
| `src/channels/mod.rs`, `telegram.rs`, `cli.rs` | `channels/` | `member_id` → operator id |
| `src/memory/{mod,hindsight}.rs` | `memory/` | bank prefix + missions re-tuned in the adapt commit; retention pre-filter rewritten for ops content |
| `src/tools/web.rs` (fetch_url: SSRF guards, html2text, wiremock tests) | `tools/web.rs` | as-is |
| `src/push.rs` (`web-push-native`, VAPID) | `channels/push.rs` | send-only channel; VAPID keygen moves into `onboard`; incident/approval notifications deep-link into the PWA |
| `static/manifest.json`, `static/sw.js` + templating route (`__SW_VERSION__`, `__VAPID_PUBLIC_KEY__`), `/api/push/subscribe`, dead-endpoint pruning, `pushsubscriptionchange` re-subscribe | web UI | the complete PWA recipe — port structure verbatim, rebrand content |
| scheduler skeleton: `supervise()`, `phase!`, watchdog atomics, compose semaphore | `scheduler/` | phases replaced with opsclaw's set |
| `src/http/{auth,auth_gates,turn_gate,ratelimit}.rs`, layer ordering, graceful shutdown | `http/` | turn_gate keys on team-global chat, not household |
| `tests/repo_parity.rs` macro shape | `tests/repo_parity.rs` | fake vs SQLite |
| `ScriptedLlm`-driven loop tests, wiremock Hindsight suite | test tree | |
| `Dockerfile`, `justfile` release flow, `deny.toml`, `clippy.toml`, `rustfmt.toml` | repo root | GHCR publish; eval gate |

**Adapt tier** (structure ports, content changes):

| gianna | opsclaw | change |
|---|---|---|
| `src/config.rs` | `config/` | env+dotenv → `~/.opsclaw/config.toml` + env overlay; keep validate()/Debug-redaction/fake-selection patterns; add the aes-gcm secret store (gianna already encrypts OAuth tokens at rest — same primitives) |
| `src/scheduler/jobs.rs` + `src/domain/job.rs` (advance, claims, retry/dead-letter) | `scheduler/jobs.rs` | Postgres → SQLite; `digest_sends` claims generalized to incident/occurrence claims |
| `src/db/postgres/` + `src/db/memory/` | `db/sqlite/` + `db/memory/` | real SQL rewritten for SQLite (WAL mode, busy_timeout; claim CAS via `UPDATE ... WHERE` + changes()); parity suite is the safety net |
| `src/agent/{mod,prompt,replay}.rs` | `agent/` | loop skeleton, error-splitting, prompt-cache ordering, replay window survive; dispatch becomes classify-then-gate through `policy::execute` |
| `src/channels/web.rs` + stream tickets | `channels/web.rs` | event vocabulary: chat / incident / approval / status |
| `src/http/state.rs` (`AppState::with_repos` wiring) | `http/state.rs` | provider set differs, pattern identical |
| `tests/e2e_flow.rs` scaffolding | `tests/e2e_flow.rs` | journeys: onboard → target add → scan → incident → approve |

**New tier** (no donor): `policy/`, `audit/`, `targets/` (executors),
`incidents/`, approvals, `runbooks/`, e-stop, external dead-man heartbeat,
risk classifier + destructive-pattern blocklist, secret scrubber, all
SRE tools (`monitor`, `systemd`, `docker`, `ssh`, `kubernetes`,
`elasticsearch`, `azure_service_bus`, `eventstore`, `prometheus`, `argocd`,
`notify`, `opsclaw_config`), Tier 2 harness, web UI content, CLI wizards
(gianna's onboarding is the style reference, not a donor), Helm chart,
docker-compose.

## 3. Build order

**Wave 0 — scaffold (sequential, main session).** Repo layout, frozen
contracts, `config/` + secret store, AGENTS.md, CI skeleton, fakes-mode
boot. *Exit: `cargo test` green; the daemon binary boots on
`Config::default()` and serves `/ready`.*

**Wave 1 — foundations (parallel, worktree agents).**
`db/` (repos, migrations, parity) · `llm/` port + usage tracking ·
`memory/` port · `channels/` port (telegram/cli/recording).
*Exit: parity suite green on SQLite; fakes daemon still boots.*

**Wave 2 — safety core (sequential, main session; this is the part that
must not be delegated carelessly).** `targets/` executors (local → ssh →
kubernetes → cloud/azure), `policy::execute`, `audit/` chain, e-stop,
risk classifier + blocklist, secret scrubber.
*Exit: Tier 1 proof that a tool cannot obtain an executor; audit
`verify` passes and detects tampering; e-stop halts mid-turn; classifier
corpus tests pass.*

**Wave 3 — the agent (parallel).** `agent/` loop + `tools/` set ·
`scheduler/` phases + scan jobs + external heartbeat · `incidents/` +
approvals · `runbooks/`.
*Exit: ScriptedLlm end-to-end: scan → fault → hypothesis → notify;
suggest-level mutation → approval → verbatim execution → audit.*

**Wave 4 — surfaces (parallel).** `http/` gateway + auth + webhook
ingestion · embedded web UI (four surfaces) · `cli/` (onboard, wizards,
doctor, daemon, estop, incidents, postmortem, runbook, memory, `ui`
tunnel) · web SSE channel.
*Exit: Tier 3 e2e journeys green.*

**Wave 5 — proof and packaging.** Tier 2 gVisor scenario suite · k3d
suite · live-eval tier + eval-gated release · docker-compose + Helm +
systemd unit · docs. *Exit: brief §13 definition of done, item by item.*

## 4. Test matrix

- **policy/audit**: classifier corpus (incl. every destructive pattern);
  no-bypass compile/test proof; chain verify + tamper detection; e-stop
  mid-turn; secret-through-every-sink scrubber test.
- **scheduler**: ported gianna tests (advance fast-forward, claim
  exactly-once, retry/dead-letter, watchdog lag-vs-stall) on SQLite.
- **agent**: ScriptedLlm scripts for approval flow, duplicate-call guard,
  injected-alert framing, error-splitting, step/deadline caps.
- **tools**: Tier 1 each — wiremock for endpoint-backed, fake executor for
  executor-backed.
- **memory**: ported wiremock Hindsight suite (retry, drain, timeouts,
  404-as-success).
- **e2e (Tier 3)**: signup/invite, onboard, target add, doctor, scan,
  incident lifecycle, approve-from-chat, estop.
- **Tier 2 scenarios** (each asserts detection, correct naming, ONE notify,
  silence after disarm): silent-baseline · cpu-single · **cpu-4way** ·
  mem-pressure · disk-fill · sigstop-deadlock · log-flood ·
  **logfile-growth** · **proc-flapping** · service-stopped · cascade ·
  **mount-scepticism** (bold = the currently-failing classes, now
  requirements). Kubernetes: crashloop · oom-eviction · failed-rollout ·
  node-pressure · **cluster-death** · helm-install smoke. All daemons under
  test run with a scrubbed, non-inherited environment.
- **Live evals**: scenario prompts against the shipped model chain,
  scheduled runs, release-gated.

## 5. Decision points to settle during build (flagged, not blocking)

- **ssh library**: lean `openssh` (wraps system ssh: ProxyJump, agent,
  known_hosts free — right for a bastion) over pure-Rust `russh`.
- **kubernetes**: `kube-rs` for API paths; `kubectl` via executor where
  exec semantics are needed.
- **azure**: lean `az` CLI through the local executor initially — uniform
  command-shaped audit records a human can replay — over SDK crates.
- **web UI stack**: gianna-style no-build vanilla JS embedded via
  `include_str!`; revisit only if the four surfaces genuinely hurt.
- **transitive `rsa` dep** (RUSTSEC-2023-0071, ignored in deny.toml) —
  SETTLED at the end of the build, revisited as planned once the auth and
  push channels existed: it stays. It arrives via jsonwebtoken (already
  trimmed to `default-features = false, features = ["rust_crypto"]`) and
  web-push-native→jwt-simple→superboring; we use no RSA path (HS256 JWT +
  ES256 VAPID), the advisory is a timing side-channel in RSA *decryption*
  we never perform, and no upstream fix exists. The alternatives — replacing
  both crates with hand-rolled HS256/ES256-JWS — trade real risk in
  security-critical code for zero reduction in reachable attack surface.
  The deny.toml ignore carries this rationale; re-check it if either crate
  is ever swapped.
- **legacy config** — SETTLED (clear refusal, not migration): machines that
  ran the zeroclaw-fork opsclaw have an old-schema `~/.opsclaw/config.toml`
  (`schema_version = 2`) — discovered on this very machine at Wave 0 boot.
  `onboard` and `doctor` detect it via `cli::legacy` and print an actionable
  refusal (move the file aside, onboard fresh) instead of a raw parse error.
  No automatic migration: the old schema is a different product generation —
  a speculative field-mapping would produce a config the operator never
  reviewed, for a daemon whose autonomy semantics differ.

Settled (DESIGN.md §7): LLM default is OpenRouter-only (evals run the same
chain); remote CLI is the small set (chat, incidents, approve/deny, estop,
status); repo is proprietary for now (no LICENSE file).

## 6. Process

Waves 1/3/4 fan out to worktree-isolated agents building against the frozen
contracts, each landing with its tests green against the fakes spine.
Wave 0/2 and all integration stay in the main session. Small direct commits
to master as work lands (no attribution trailers); nothing is pushed to any
remote without an explicit ask. Ported code cites its gianna source file in
the commit message, not in code comments.
