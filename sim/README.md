# sim/ — Tier 2 fault-injection harness

The acceptance test (brief §9, DESIGN.md §6 "Tier 2"): a real fault, injected
on a real (gVisor-sandboxed) target, must be detected, named correctly, and
notified exactly once — or, for a healthy target, produce silence.

## How it works

`sim/target.Dockerfile` builds a Debian target image with `stress-ng`,
`sshd`, and a handful of fake services (`fake-worker`, `fake-web`,
`log-emitter`) supervised by `supervisord` (stands in for systemd — no
cgroup/dbus inside a container). The target runs under
`--runtime=runsc` (gVisor), which is what makes `mount-scepticism` a real
fault: gVisor's host-bind-mount handling genuinely makes `df` report
misleading numbers, not a mocked approximation of that behaviour.

Each scenario in `sim/scenarios/<name>/` is three files:

- `arm.sh` — injects the fault against the running container (`$SIM_CONTAINER`
  env var), then **verifies the fault is real** (reads `/proc`, `df`,
  `supervisorctl status`, etc. — never trusts its own exit code alone).
- `disarm.sh` — reverses the fault and verifies the target is clean again.
- `expected.json` — what a daemon pointed at this target should do. Schema:
  `sim/expected.schema.json`.

`sim/run.sh` is the orchestrator: builds the image once, then per scenario —
start container → wait for sshd → arm → boot a real `opsclaw` daemon against
the target and assert detection (`sim/daemon-harness.sh`, shared with
`k3d/run.sh` — see "What's wired today" below) → disarm → verify clean →
tear down. Idempotent; safe to re-run.

## Running

```sh
sim/run.sh                  # every scenario, sequentially, one slot
sim/run.sh cpu-single        # one scenario
sim/run.sh cpu-single mem-pressure   # a subset
sim/run.sh --parallel        # every scenario in parallel, isolated slots
sim/run.sh --keep            # leave containers running after a pass (debugging)
```

Requires `docker info | grep runsc` to show the `runsc` runtime registered —
`sim/run.sh` fails fast with a clear message otherwise rather than silently
degrading to `runc` (which would make `mount-scepticism` meaningless).

Containers are named `opsclaw-sim-<slot>` (`opsclaw-sim-default` for a
sequential run, `opsclaw-sim-slot1`, `opsclaw-sim-slot2`, ... in parallel
mode) so parallel scenario runs never collide. Each run generates a fresh
ephemeral ed25519 keypair per scenario invocation — no key is baked into the
image.

## What's wired today

**Fault injection layer:** image build, gVisor-sandboxed target boot, ssh
reachability, every scenario's arm/disarm round-trip with real verification
that the fault is present and then absent (real CPU load, real memory
pressure, real full mount, a really-SIGSTOPped process, real restart churn,
a real decoy tmpfs that fools naive `df` reading).

**Daemon-detection assertion (brief §9, `sim/daemon-harness.sh`):**
`sim/run.sh` boots a REAL `opsclaw` daemon (the same binary `main.rs`
builds) as a subprocess, under a **scrubbed, non-inherited environment**
(DESIGN.md §6 — `env -i` plus an explicit allowlist, so an ambient real
credential on the host can never flip the daemon into live mode mid-test),
against a throwaway `OPSCLAW_HOME` and a generated `config.toml` declaring
the sim container as an `ssh` target (`ssh://root@127.0.0.1:<mapped-port>`,
the ephemeral key `sim/run.sh` generates, `ssh_strict_host_key_checking =
"accept-new"` since the container's host key is fresh every run). Two tiers:

- **Deterministic (always runs, no LLM/network):** the daemon boots on the
  generated config; `doctor`'s probe reaches the target through the same
  executor construction path the daemon boots with; the seeded scan job
  actually fires a tick against the target; the daemon survives the armed
  fault; for `must_notify=false` scenarios, the incidents table stays at
  zero rows (necessary but not sufficient — the fakes-mode LLM,
  `src/llm/fakes.rs` `FakeLlm`, never calls any tool, so this can't
  distinguish "correctly judged healthy" from "incapable of ever
  alerting"). Every assertion the deterministic tier cannot make (the actual
  "was the fault detected and named correctly" claim for `must_notify=true`
  scenarios) is printed as an explicit `SKIPPED` line, never silently
  omitted.
- **Live (`OPSCLAW_LIVE_EVALS=1` + `OPENROUTER_API_KEY`, same gate as
  `tests/evals.rs`/`docs/EVALS.md`):** the shipped provider chain runs for
  real; asserts exactly one incident (or zero, for `must_notify=false`)
  across two observed scan ticks — the anti-spam claim — with severity
  matching `expected.json`. "Correctly named" (`fault_class`) is NOT checked
  even in live mode: `opsclaw_notify` (`src/tools/notify.rs`) persists only
  a SHA-256 fingerprint of `(target, fault_class, resource)`, never
  `fault_class` itself, so a subprocess daemon has no honest way to read it
  back — `tests/evals.rs`'s `notify_discipline`/`injection_resistance` cases
  are where that exact check happens, via in-process capture of the tool
  call's raw args.

Run it live:

```sh
OPSCLAW_LIVE_EVALS=1 OPENROUTER_API_KEY=sk-or-... sim/run.sh
```

## Adding a scenario

1. `mkdir sim/scenarios/<name>`
2. Write `arm.sh` / `disarm.sh` — idempotent, self-contained, verify the
   fault (not just the command that caused it).
3. Write `expected.json` against `sim/expected.schema.json`.
4. `chmod +x arm.sh disarm.sh`.
5. `sim/run.sh <name>` to validate in isolation before running the full suite.
