# Tier 2 — Sim harness status

Driver: `./dev/test.sh tier2` → `dev/sim/harness/run.sh`.
Verdict: `target/tier2-verdict.json`.

Parallelism: `./dev/test.sh tier2 --parallel N --bring-up` runs N
scenarios concurrently. Each "slot" is a fully isolated environment
(separate sim-target, webhook-sink, OpsClaw daemon, bridge network,
ports, state dir) — alerts from slot A never contaminate slot B's
assertions. Slot lifecycle lives in `dev/sim/harness/slot.sh`.

## What Tier 2 guarantees

When the full suite reports `verdict: PASS`:

- OpsClaw's autonomous daemon starts under gVisor sandboxing.
- Heartbeat ticks run the seeded scan tasks against a real SSH target.
- Agent observes kernel-mediated resource state.
- Agent correctly detects each injected fault category.
- Agent calls `opsclaw_notify` with a payload matching the scenario's
  declared expectation.
- Agent does not spam. Agent stays silent on healthy baselines.

## Latest run (parallelism=3, gpt-5.4)

**2 PASS / 9 total in 971s (16 min).**

| Scenario | Verdict | Why |
|---|---|---|
| baseline_silent | PASS* | *Assertion bug: the run pre-dated the assertion fix that catches alerts under `alert_present:false`. Would FAIL on rerun due to the env issue below. |
| cascade_disk_to_crash | PASS | Composite fault detected, dedups, resolves. |
| cpu | FAIL | Agent didn't flag 4-way CPU saturation. Real agent-behaviour gap. |
| deadlocked_but_running | FAIL | Agent alerted DiskFull (env issue, not the SIGSTOP we armed). |
| disk_full | FAIL | Detected correctly; assertion too strict (blocked "memory" mention). |
| log_flood | FAIL | Agent didn't notice log file growth. Real agent-behaviour gap. |
| memory | FAIL | Detected + dedup PASS; 2 lagging post-disarm alerts vs grace of 1. |
| process_flapping | FAIL | Agent didn't recognise the restart cadence. Real gap. |
| service_stopped | FAIL | Agent alerted DiskFull instead (env issue). |

## Findings in three buckets

### Bucket A — Sim environment (needs fix before suite is credible)

gVisor's 9p mounts for host-backed files (`/etc/resolv.conf`,
`/etc/hosts`, `/etc/hostname`) show up in `df` at ~87%. Any agent
that runs `df -h` gets a legitimate-looking "disk pressure" signal
and alerts on that, masking the real fault. This poisoned
`deadlocked_but_running`, `service_stopped`, and `baseline_silent`.

**Fix**: in `sim-target/entrypoint.sh`, bind-mount a tmpfs over
those paths so `df` reports sane values. Alternatively, keep the
real mounts but teach the seed prompt to filter them. The former is
cleaner — the agent shouldn't have to learn sim-specific quirks.

### Bucket B — Scenario assertions too strict

- `disk_full`: drop `content_must_not_mention: ["memory"]`. The agent
  can legitimately mention memory while discussing disk.
- `memory` phase_disarm: raise `lagging_alerts_allowed` from 1 to 2.
  Disarm takes a few ticks to propagate; the agent is correct to
  re-alert until it observes the clear.

### Bucket C — Real OpsClaw behaviour gaps (tickets, not harness bugs)

- `cpu`: gpt-5.4 doesn't treat high CPU utilisation as concerning
  without context. Seed prompt could add "high CPU / load is a
  warning" or similar.
- `log_flood`: agent doesn't actively sample filesystem growth.
  Would benefit from a `du -sh` or `ls -la /var/log/*` in the scan.
- `process_flapping`: detecting restart-cadence requires comparing
  process start times across ticks. Current seed prompt doesn't
  teach this; agent treats each tick as independent.

These three are **genuine agent-behaviour defects surfaced by the
sim** — exactly what Tier 2 is for. Fixes live in prompt/tool work,
not the harness.

## Scenarios

| Scenario | Category | Status |
|---|---|---|
| memory | resource | active |
| cpu | resource | active |
| disk_full | resource | active |
| service_stopped | service | active |
| process_flapping | service | active |
| log_flood | filesystem | active |
| deadlocked_but_running | pathological | active |
| baseline_silent | negative | active |
| cascade_disk_to_crash | composite | active |
| port_closed | network | **skipped** (gVisor netstack lacks iptables) |
| ssh_blackhole | honesty | **skipped** (same netfilter limitation) |

Skipped scenarios keep their arm/disarm/README but have their
expected.json renamed to `expected.json.skip`.

## Known limitations

- **gVisor netfilter.** No iptables/netfilter support in the gVisor
  netstack. Two workarounds if needed: switch affected scenarios to
  runc (losing /proc fidelity for those), or run a Kata-backed
  target container.
- **gVisor 9p host mounts contaminate df.** See Bucket A.
- **No structured event log.** Assertions read the webhook-sink's
  JSONL. Future: stream daemon events for richer assertions (tool
  calls, heartbeat ticks).
- **Real LLM required.** Each full run costs roughly $0.50–$2.00.
  No mock provider yet.

## How to add a scenario

1. `mkdir dev/sim/scenarios/<name>`.
2. `arm.sh` — runs inside the sim-target container to induce the
   fault. Return quickly (fork long-running processes).
3. `disarm.sh` — restores the baseline.
4. `expected.json` — three-phase assertion DSL. See
   `dev/sim/scenarios/memory/expected.json`.
5. `README.md` — one paragraph.

Run just your new scenario: `./dev/test.sh tier2 --only <name>`.

## Handoff points

Tier 1 (component-level tool tests) and Tier 3 (flow tests) stub
out as `MISSING` verdicts today. `./dev/test.sh ready` aggregates
all three. Tier 1 is owned by a sibling agent; Tier 3 is future
work.
