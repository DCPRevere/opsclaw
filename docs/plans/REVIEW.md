# OpsClaw review — 2026-11-04

Scope: current `master` (v0.3.0, 54k lines of Rust), with a focus on diagnosis.
Checked by reading the code and running the suites; findings marked
**confirmed** were reproduced.

## Health

| Check | Result |
|---|---|
| `cargo fmt --check` | pass |
| `cargo test` | pass — 1,139 tests, 0 failed (live evals skipped: no key) |
| `cargo clippy -D warnings` | **fail** on stable 1.99: 94 `double_must_use`, 3 deprecated `fetch_update` |
| Live evals / `sim/` / `k3d/` | not run (need OpenRouter key, gVisor, k3d) |

## Strong

- One policy choke point for every target command, with e-stop, scope
  checks, rate caps and a hash-chained audit log. The isolation work in v0.3
  is careful.
- Untrusted data framing for alerts, logs and command output.
- Mandatory scan checklist, written after a real missed crashloop.
- Real fault-injection harnesses: 12 `sim/` scenarios on a gVisor target,
  5 `k3d/` scenarios.
- Safe failure: durable idempotent chat turns, spend cap including Hindsight.

## Problems, most serious first

### 1. Long investigations forget the task — confirmed bug

`src/agent/replay.rs` `shrink_history`, called every step once history
passes 40k tokens:

- Keeps only the last 12 turns. After about 9 tool calls the original
  request (the scan checklist, or the alert) is dropped. Reproduced with a
  unit test: 10 large `kubernetes` results → the task message is gone.
  Heartbeat scans (32 steps, large kubectl output) are exactly where this
  happens.
- The "3 exchanges kept verbatim" are in fact cut to 1,200 characters,
  because `cap_tool_result` runs before the collapse.
- Truncation keeps the head of the output. Errors are usually at the tail
  of logs.
- Older evidence collapses to 160-character markers, which is Datadog's
  documented failure: the right clue is found, then lost before the
  conclusion.
- The shrunk history can start with an assistant turn, which some providers
  reject.

Fix: always pin the turn's task message; truncate head plus tail; summarise
evidence into a running findings list instead of discarding it.

### 2. Raw tool output is unbounded

Executor output goes to the model uncapped on first return
(`src/tools/executor.rs`). One `kubectl get pods -A` on a large cluster can
fill the context and trigger problem 1 straight away. Cap per call, keeping
head and tail, and say how much was dropped.

### 3. The Kubernetes tool can't see the usual crash evidence

`src/tools/kubernetes.rs`:

- `logs` is fixed at `--tail=200`, with no `--previous`. A crashlooping
  pod's reason lives in the previous container's logs.
- No `-c <container>`, so `logs` fails on any multi-container pod.
- No `--since`; events can't be sorted or filtered; no `top`.

There is no raw-kubectl escape hatch, so the model cannot work around these
gaps.

### 4. Alert intake is fragile and expensive

`src/agent/dispatch.rs` `WebhookIngest`:

- The full agent turn runs inside the HTTP request (up to 120 s plus LLM
  time). Sender timeouts and retries can cause duplicate investigations.
- No dedup: each Alertmanager repeat notification starts a new full LLM
  investigation. Resolved notifications start one too.
- Webhook turns take the exclusive gate, so a burst of alerts queues behind
  each other and blocks chat.
- The Alertmanager route requires an HMAC header that Alertmanager cannot
  produce, so a signing shim is needed. Accepting Alertmanager's native
  bearer-token auth would remove it.

Fix: return 202 at once, queue the alert, dedup by alert fingerprint and
group key, and skip or short-circuit resolved notifications.

### 5. Nothing measures diagnosis quality

- `tests/evals.rs`: 4 live cases, all about behaviour (scepticism,
  restraint, injection, notifying once).
- Live `sim/` checks incident count and severity, not whether the fault was
  named correctly. `sim/README.md` says `fault_class` isn't stored, but
  migration `0006` stores it, so the check is now possible and the README
  is stale.
- The scenarios are single-host and synthetic. None has a cause in another
  service (database down → app errors, bad deploy → crashloop).

### 6. Diagnosis structure is thin

- The hypothesis is one free-text string.
- No change timeline, no dependency map, no baselines (see `DIAGNOSIS.md`).
- Tool calls run one at a time, and interactive turns get 16 steps / 120 s,
  which is tight for a real investigation.
- Log search is Elasticsearch only (Loki is a stub); no traces.

### 7. CI is probably red

The toolchain isn't pinned (no `rust-toolchain.toml`), and CI installs the
latest stable. Clippy 1.99 now fails with `-D warnings`. Pin the toolchain,
or fix the 97 lints (mostly removing redundant `#[must_use]`).

### 8. Stale docs

- `docs/DESIGN.md` mentions the reference estate's "nine real postmortems";
  `docs/REFERENCE.md` is now a generic profile.
- `sim/README.md` on `fault_class` (see 5).

## Suggested order

1. Fix problem 1 (bug) and cap tool output (2). Small and high impact.
2. Kubernetes `logs --previous`, `-c`, `--since`; sorted events (3).
3. Pin the toolchain (7).
4. Diagnosis scoring: assert `fault_class` in live `sim/`, add causal
   scenarios (5).
5. Async, deduped alert intake (4).
6. Then `DIAGNOSIS.md`: change timeline → hypothesis tree → dependency map.
