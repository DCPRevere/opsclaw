# Testing

OpsClaw has four layers of tests, each answering a different question. Run the layer that matches what you changed.

| Layer | Question it answers | Speed | Command |
|---|---|---|---|
| Unit | Does this function compute the right value? | seconds | `cargo test --lib` |
| Component / integration / system | Do these modules wire together correctly? | seconds–minutes | `cargo test --workspace` |
| Tier 1 | Does each tool talk to its real backend correctly? | minutes | `dev/test.sh tier1` |
| Tier 2 | Does the running agent detect and alert on real faults? | ~15 min | `dev/test.sh tier2` |
| Tier 3 | Do the user-facing flows (setup, doctor, daemon) work end-to-end? | minutes | `dev/test.sh tier3` |

`dev/test.sh ready` runs Tier 1 + 2 + 3 and writes a single `target/ready-verdict.json`. That's the gate for "is this build production-ready?"

## TL;DR — what to run when

- **Edited a function** → `cargo test --lib`
- **Edited config / channels / providers / agent loop** → `cargo test --workspace`
- **Edited a tool that talks to a real service** (Prometheus, kube, Loki, …) → `dev/test.sh tier1`
- **Edited the daemon, the heartbeat seed, or `opsclaw_notify`** → `dev/test.sh tier2`
- **Edited setup / doctor / CLI flows** → `dev/test.sh tier3`
- **Cutting a release** → `dev/test.sh ready`

## Unit tests

Inline `#[test]` functions next to production code. About 3,300 of them, covering config, agent loop, security policy, channels, and providers most heavily.

```bash
cargo test --lib                     # all unit tests
cargo test --lib -p opsclaw          # one crate
cargo test --lib config::schema::    # one module
```

These are fast and have no external dependencies. They run in CI on every commit.

## Workspace tests (component / integration / system / live)

Larger tests live in `tests/` of each crate, split into four directories:

- `tests/component/` — one subsystem at a time (config persistence, provider resolution, security, gateway).
- `tests/integration/` — multiple subsystems wired together (agent + memory + channels).
- `tests/system/` — full application boot, no external services.
- `tests/live/` — real third-party APIs. Marked `#[ignore]`; skipped by default.

```bash
cargo test --test component
cargo test --test integration
cargo test --test system
cargo test --test live -- --ignored   # needs API credentials
cargo test --workspace                 # everything except live
```

Shared test fixtures live in `tests/support/`:

- `MockProvider` — scripted FIFO LLM responses; `RecordingProvider` captures requests for assertion.
- `EchoTool`, `CountingTool`, `FailingTool`, `RecordingTool` — mock tools.
- `build_agent()` / `build_agent_xml()` — construct test agents with the right dispatcher.
- `LlmTrace` / `TraceExpects` — declarative trace assertions ("expect tool X called", "response contains Y").
- `make_memory()`, `make_observer()` — in-memory backends.

CI runs these via `cargo nextest run --locked` for parallelism.

## Production-readiness tiers

Unit and workspace tests prove the code *compiles to the right shape*. They don't prove OpsClaw responds to a real outage correctly. Three higher-level tiers do.

One driver:

```bash
dev/test.sh tier1     # tools
dev/test.sh tier2     # agent behaviour under real faults
dev/test.sh tier3     # user-facing flows
dev/test.sh ready     # all three; writes target/ready-verdict.json
```

### Tier 1 — tool-level integration

For each tool that talks to a real backend (Prometheus, kube, Loki, ELK, PagerDuty, RabbitMQ, Postgres, …), spin up that backend in Docker, exercise the tool, and assert the response shape. This is what catches "we updated to the kube 0.95 client and the namespace field moved." Owned by a sibling agent; emits a verdict to `target/tier1-verdict.json`.

### Tier 2 — sim-based behavioural testing

Tier 2 answers the central question: **does the running agent actually detect, alert on, and stop spamming about real faults?**

How it works:

1. Boot a sim-target container under gVisor (`runsc`), which gives the agent a real, kernel-mediated `/proc` and cgroup view — not a wrapper that lies about resource state.
2. Boot the OpsClaw daemon pointed at it, with `[notifications].webhook_url` aimed at a webhook-sink container that records every alert to `requests.jsonl`.
3. Run a scenario: inject a real fault (`stress-ng`, `fallocate`, `kill -STOP`, …), wait, clear it.
4. Read `requests.jsonl` and assert the agent fired the right alert at the right time, didn't repeat it, and went quiet on resolution.

What we can simulate (`dev/sim/scenarios/`):

| Category | Scenarios | Fault mechanism |
|---|---|---|
| Resource pressure | `memory`, `cpu`, `disk_full` | `stress-ng`, `fallocate` against cgroup caps (8 GB / 4 CPU / 200 MB tmpfs) |
| Service lifecycle | `service_stopped`, `process_flapping`, `deadlocked_but_running` | `kill -TERM`, kill+relaunch loop, `kill -STOP` |
| Filesystem | `log_flood` | tight loop appending to `/var/log/test.log` |
| Negative | `baseline_silent` | no fault — agent must stay silent |
| Composite | `cascade_disk_to_crash` | disk fill + SIGSTOP concurrently |
| Network (skipped) | `port_closed`, `ssh_blackhole` | iptables — currently blocked by gVisor netstack |

Each fault is kernel-mediated. The agent observes the target the same way it would in production: SSH in, look at `/proc`, run `df`, etc.

Each scenario asserts three phases:

- `phase_arm` — fault is live. Expect an alert with matching severity / category / keywords. Negative scenarios expect *silence* instead.
- `phase_dedup` — fault persists. Expect at most `extra_alerts_max` further alerts.
- `phase_disarm` — fault cleared. Expect either a resolution alert or silence, with `lagging_alerts_allowed` ticks of grace for in-flight repeats.

Phase definitions live in each scenario's `expected.json`. The assertion engine is `dev/sim/harness/assert_phase.py`.

**Parallel execution.** `dev/test.sh tier2 --parallel N --bring-up` runs N scenarios concurrently. Each *slot* is fully isolated:

- Its own sim-target, webhook-sink, OpsClaw daemon
- Its own bridge network and SSH/webhook ports
- Its own state directory and `requests.jsonl`

Alerts from slot A cannot contaminate slot B's assertions. `dev/sim/harness/slot.sh` owns slot lifecycle; `dev/sim/harness/run.sh` is a job-pool dispatcher that pops scenarios off a queue. Budget ~1 GB RAM + 1 CPU + concurrent LLM API usage per slot.

**Adding a scenario.** Copy an existing directory under `dev/sim/scenarios/`. You need four files:

- `arm.sh` — induces the fault inside the sim-target. Fork long-running processes; return quickly.
- `disarm.sh` — restores the baseline.
- `expected.json` — the three-phase assertion manifest.
- `README.md` — one paragraph on what's being tested.

Run just yours: `dev/test.sh tier2 --only <name>`.

**Prerequisites.**

- `dev/sim/.env` with `OPENAI_API_KEY=…` (gitignored).
- gVisor installed once: `sudo runsc install && sudo systemctl restart docker`.
- Each full Tier 2 run consumes roughly 200k–800k LLM tokens.

Latest run results and the known gaps (env quirks, over-strict assertions, real agent gaps) are tracked in [TIER2_STATUS.md](../TIER2_STATUS.md).

### Tier 3 — user-facing flows

End-to-end checks for `opsclaw setup`, `opsclaw doctor`, daemon boot, emergency-stop, etc. Currently a stub emitting `MISSING`; future work.

## Single-developer simulation playground

The Tier 2 harness is for automated assertions. If you just want to drive the sim by hand — fire a fault, watch what the agent does, tear it down — use `sim.sh`:

```bash
./dev/sim/sim.sh up            # start environment
./dev/sim/sim.sh fault memory  # inject a fault
./dev/sim/sim.sh webhooks      # tail the alert stream
./dev/sim/sim.sh down          # tear down
```

See [simulation.md](simulation.md) for the full command set.

## CI

Inherited from ZeroClaw:

- `cargo fmt --all` — formatting
- `cargo clippy --all-targets` — lints
- `cargo nextest run --locked` — workspace tests, parallel
- `cargo audit` — dependency CVE scan
- `cargo deny check licenses sources` — license compliance

The production-readiness tiers (`dev/test.sh ready`) are not yet gated in CI — they're a manual pre-release check.
