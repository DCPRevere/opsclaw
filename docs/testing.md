# Testing

OpsClaw inherits ZeroClaw's test suite and adds SRE-specific tests on top.

## Running tests

```bash
# All unit tests (inline in src/)
cargo test --lib

# Component tests (config, gateway, security, providers in isolation)
cargo test --test component

# Integration tests (agent orchestration, channel routing, memory)
cargo test --test integration

# System tests (full-stack workflows)
cargo test --test system

# Live E2E tests (requires API credentials, skipped by default)
cargo test --test live -- --ignored

# Everything
cargo test --locked

# Benchmarks (tool dispatch, memory, agent turn cycle)
cargo bench
```

CI uses `cargo nextest run --locked` for parallel execution.

## Test structure

### Unit tests (in `src/`)

Inline `#[test]` functions alongside production code. ~3,300 tests covering every major module. Run with `cargo test --lib`.

Heaviest coverage: config/schema, agent loop, security policy, channels, providers.

### External test harnesses (in `tests/`)

Four tiers:

- `tests/component/` — isolated subsystem tests (config persistence, provider resolution, security, gateway)
- `tests/integration/` — multi-component tests (agent robustness, channel routing, memory restart persistence)
- `tests/system/` — full application integration
- `tests/live/` — real API calls, marked `#[ignore]`

### Test support (`tests/support/`)

Shared infrastructure:

- `MockProvider` — scripted FIFO responses. `RecordingProvider` captures requests for assertion.
- `EchoTool`, `CountingTool`, `FailingTool`, `RecordingTool` — mock tools.
- `build_agent()` / `build_agent_xml()` — construct test agents with the right dispatcher.
- `LlmTrace` / `TraceExpects` — declarative trace-based assertions ("expect tool X called", "response contains Y").
- `make_memory()`, `make_observer()` — in-memory test backends.

## OpsClaw Phase 1 tests

Test files exist in `tests/component/` but are commented out in `mod.rs` until the corresponding implementation is built. Uncomment each as you go.

### `target_config.rs` (Phase 1a)

14 tests. Covers `[[targets]]` config parsing and validation:

- SSH targets require host, user, key
- Local targets work without SSH fields
- Multiple targets parse correctly
- Duplicate names rejected at validation
- Autonomy defaults to `observe`, rejects invalid levels
- Unknown target types rejected
- Context file is optional
- Config without targets is valid

### `secret_store.rs` (Phase 1b)

10 tests. Covers encrypted credential storage:

- Store/retrieve round-trip
- Overwrite existing secret
- Get nonexistent returns `NotFound`
- Delete, list names
- Values never stored as plaintext on disk
- Persists across reopen
- Rejects empty name/value

### `ssh_tool.rs` (Phase 1c)

11 tests. Covers the `Tool` trait implementation:

- Name is `ssh`, description mentions remote execution
- Schema requires `target` and `command`, does not expose key/password parameters
- Rejects missing target, missing command, unknown target
- Output never contains SSH key material (even on error)
- Observe mode blocks write commands (`rm`, `systemctl restart`, `docker stop`, `kill`, `reboot`)
- Observe mode allows read commands (`uptime`, `ps aux`, `df -h`, `docker ps`)
- Output includes exit code
- Schema accepts optional `timeout_secs`

### `discovery_scan.rs` (Phase 1d)

14 tests. Covers snapshot parsing and drift detection:

- Snapshot structure has all sections, serializes to JSON
- Parsers for `ps aux`, `ss -tlnp`, `docker ps`, `df -h`, `/etc/os-release`
- Database detection from ports and process names (including non-standard ports)
- Drift detection: new container, stopped container, identical = no diff
- All scan commands are read-only (checked against write-command prefixes)

### `monitoring_loop.rs` (Phase 1f)

12 tests. Covers health check cron job construction:

- Job type is `agent`, session is `isolated`
- Tool allowlist restricts to `ssh` + `memory_recall` + `memory_store` (SSH targets) or local exec + memory (local targets)
- System prompt includes target name, snapshot data, and user context
- Default interval 5 minutes, minimum 30 seconds enforced
- Delivery config targets the configured channel
- One health check created per target from config

## Simulation environment

A Docker-based simulation environment lets you run OpsClaw end-to-end against a fake target and inject faults (memory pressure, disk full, container crashes, etc.) to verify detection and alerting. See [simulation.md](simulation.md) for details.

```bash
./dev/sim/sim.sh up            # start environment
./dev/sim/sim.sh fault memory  # inject a fault
./dev/sim/sim.sh webhooks      # see the alert
./dev/sim/sim.sh down          # tear down
```

## CI

Inherited from ZeroClaw:

- `cargo fmt --all` — formatting
- `cargo clippy --all-targets` — lints
- `cargo nextest run --locked` — all tests in parallel
- `cargo audit` — dependency vulnerability scan
- `cargo deny check licenses sources` — license compliance
