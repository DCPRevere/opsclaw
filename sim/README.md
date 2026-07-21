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
start container → wait for sshd → arm → (today: stop here and report; see
TODO below) → disarm → verify clean → tear down. Idempotent; safe to re-run.

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

## What's wired today vs. TODO

**Working today:** image build, gVisor-sandboxed target boot, ssh
reachability, every scenario's arm/disarm round-trip with real verification
that the fault is present and then absent (real CPU load, real memory
pressure, real full mount, a really-SIGSTOPped process, real restart churn,
a real decoy tmpfs that fools naive `df` reading).

**TODO (later wave — daemon sim-runner integration):** `sim/run.sh` does not
yet point a live `opsclaw` daemon at the armed target and assert detection.
The wiring point is marked inline in `sim/run.sh` with `TODO(daemon-integration)`,
immediately after arm and before disarm. Once the daemon has a way to load a
target pointed at `ssh://root@127.0.0.1:<mapped-port>` with the ephemeral key
sim/run.sh already generates, that TODO block becomes:

1. Configure/point the daemon at the scenario's `fq_target`.
2. Wait for (or force) a scan tick.
3. Assert `opsclaw_notify` was called exactly once when `expected.json.must_notify`
   is true (payload's `fault`/`severity` matching), or zero times when false.
4. Assert no further notify calls fire while the fault stays armed
   (anti-spam, brief §6).

Run the daemon in that future integration with a **scrubbed, non-inherited
environment** (DESIGN.md §6) so an ambient real credential on the test host
can never flip the daemon into live mode mid-test.

## Adding a scenario

1. `mkdir sim/scenarios/<name>`
2. Write `arm.sh` / `disarm.sh` — idempotent, self-contained, verify the
   fault (not just the command that caused it).
3. Write `expected.json` against `sim/expected.schema.json`.
4. `chmod +x arm.sh disarm.sh`.
5. `sim/run.sh <name>` to validate in isolation before running the full suite.
