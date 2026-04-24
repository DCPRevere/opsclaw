# AGENTS.md

Guidelines for AI agents working in this repo.

## Vision

`OpsClaw` is a fork of `zeroclaw`. It is an agent designed to work as an SRE.

## Workspace layout

The upstream zeroclaw runtime is split across many `zeroclaw-*` crates. Do not add opsclaw-specific logic to any of them.

Upstream (zeroclaw) crates:

- `crates/zeroclaw-api` — public API surface.
- `crates/zeroclaw-channels` — channel implementations (Matrix, WhatsApp, etc.).
- `crates/zeroclaw-config` — config schema, secret store, policy, workspace.
- `crates/zeroclaw-gateway` — HTTP gateway.
- `crates/zeroclaw-hardware` — hardware integrations.
- `crates/zeroclaw-infra` — shared infrastructure glue.
- `crates/zeroclaw-macros` — proc macros.
- `crates/zeroclaw-memory` — memory/context store.
- `crates/zeroclaw-plugins` — plugin loading.
- `crates/zeroclaw-providers` — LLM provider adapters.
- `crates/zeroclaw-runtime` — agent runtime and scheduler.
- `crates/zeroclaw-tool-call-parser` — tool-call parsing.
- `crates/zeroclaw-tools` — built-in tools.
- `crates/zeroclaw-tui` — terminal UI.

OpsClaw and independent crates:

- `crates/opsclaw` — autonomous SRE agent built on zeroclaw (SSH tools, k8s, incident memory, runbooks, setup wizard).
- `crates/robot-kit` — robotics/embedded toolkit. Independent of zeroclaw and opsclaw.
- `crates/aardvark-sys` — low-level system bindings.

When adding a feature, put it in the right crate. Blurring the zeroclaw/opsclaw boundary creates coupling that's hard to undo.

Default to putting it in `opsclaw` so that we can pull from the upstream in the future.

### Re-export shims under `src/`

Files under the top-level `src/` directory (e.g. `src/approval/mod.rs`, `src/channels/slack.rs`) are thin re-export shims of the form `pub use zeroclaw_<crate>::<module>::*;`. They are not canonical — treat them as aliases and edit the real code in the corresponding `crates/zeroclaw-*` crate. Grep the upstream crates before assuming a module is opsclaw-owned.

## Design rules

- Program to traits, not implementations. Extend existing abstractions (`Tool`, `Provider`, `Channel`, `Peripheral`, etc.) before inventing new ones.
- Every command that touches a remote system must go through the audit log. Do not bypass it.
- Secrets are referenced by name in config; their values live in the encrypted store. Never write a secret value into a config file or log.

## The autonomous loop

`opsclaw daemon` does not implement its own polling loop. It launches the upstream zeroclaw daemon (`zeroclaw_runtime::daemon::run`), which owns four concurrent subsystems: gateway, channels, heartbeat, and scheduler. The heartbeat subsystem is the autonomous loop — it reads persistent tasks from `HEARTBEAT.md`, runs an adaptive-interval tick, optionally asks the LLM in Phase 1 whether any tasks need running, executes the chosen tasks in Phase 2, recalls and consolidates memory across ticks, and has a dead-man's switch that escalates if ticks stop.

OpsClaw extends this loop from its own crate only — no upstream edits. Two hooks:

- **SRE tools at agent-run time** — `crates/opsclaw/src/daemon_ext.rs::register_sre_tools` registers the opsclaw tool registry (ssh, monitor, kube, pagerduty, loki, prometheus, elk, systemd, …) via the runtime's existing `register_peripheral_tools_fn`. The slot is generic — only its name is peripheral-flavoured — and opsclaw does not use hardware peripherals, so we reuse it. Every agent run the runtime launches (heartbeat, gateway, channels) sees these tools.
- **Per-project scan tasks** — on first boot `daemon_ext::seed_heartbeat_file` writes one `[high]` scan task per `[[projects]]` entry into `HEARTBEAT.md`. A user-authored file is never overwritten; only a missing file or the upstream placeholder gets seeded.

Consequences for changes:

- To add a new SRE capability that the autonomous loop should exercise, implement it as a `Tool` and add it to `crates/opsclaw/src/tools/registry.rs::create_opsclaw_tools`. Do not wire it into `daemon_ext` directly and do not reach into the runtime.
- To change cadence, two-phase behaviour, dead-man's switch, etc., configure the upstream `[heartbeat]` section — do not add a parallel loop in opsclaw.
- If a change genuinely needs runtime surface that isn't exposed, upstream it to `zeroclaw-runtime` rather than vendoring a modified copy. The whole point of the peripheral-tools reuse is to avoid drift.

## Build and test

```sh
cargo build                          # debug
cargo build --release                # size-optimized (lto=fat, stripped)
cargo build --profile release-fast   # faster local release builds
cargo test --workspace               # run all tests
```

Feature flags gate optional capabilities (Prometheus, Matrix, WhatsApp, OpenTelemetry). Check `Cargo.toml` before assuming a dependency is available.

### Production-readiness testing

Unit tests verify correctness at the function boundary; they do not prove that OpsClaw runs correctly as a whole. Three harnesses exist above that, driven by a single top-level script:

```sh
dev/test.sh tier1      # component-level tool tests (cargo integration tests)
dev/test.sh tier2      # sim harness: real faults, real agent, asserted responses
dev/test.sh tier3      # flow harness: onboarding, daemon, doctor, estop, etc.
dev/test.sh ready      # runs all three, emits target/ready-verdict.json
```

Tier 2 is the one that answers "does OpsClaw actually respond to incidents correctly?" It runs the opsclaw daemon against a gVisor-sandboxed target, injects real cgroup-bounded pressure (stress-ng, fallocate, SIGSTOP, log-flood), and asserts the agent detects the fault, calls `opsclaw_notify` with a payload matching the scenario's `expected.json` manifest, and does not spam. See `TIER2_STATUS.md` for the covered scenarios and known gaps (iptables-based scenarios are blocked by gVisor's netstack).

Scenario layout: each lives at `dev/sim/scenarios/<name>/` with `arm.sh`, `disarm.sh`, `expected.json`, and `README.md`. To add one, copy an existing directory and adjust; run just your new scenario with `dev/test.sh tier2 --only <name>`.

Tier 2 is parallelisable. `dev/test.sh tier2 --parallel 3 --bring-up` runs three scenarios concurrently across three isolated "slots" — each slot is its own sim-target + webhook-sink + OpsClaw daemon on its own bridge network, with per-slot SSH/webhook ports and state directories. `dev/sim/harness/slot.sh` owns slot lifecycle; the orchestrator in `run.sh` maintains a job pool. Each slot costs ~1 GB RAM + 1 CPU + concurrent LLM API usage. Serial and parallel runs produce identical assertions because every slot has its own `requests.jsonl` alert stream.

Tier 2 requires `dev/sim/.env` with `OPENAI_API_KEY=…` (gitignored). It runs under gVisor (`runsc`); install once with `sudo runsc install && sudo systemctl restart docker`.

## What not to change

- `docs/` — user-facing documentation, not auto-generated. Edit deliberately.
- The audit log format — it is hash-chained and append-only by design. Do not alter the chain structure.
- Secret encryption in `Config::save()` — all secrets must remain encrypted at rest.
