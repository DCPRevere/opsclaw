# k3d/ — Tier 2 kubernetes fault-injection harness

The kubernetes half of the acceptance test (DESIGN.md §6 "Tier 2,
kubernetes"): scenarios run against a throwaway **k3d** cluster — opsclaw on
the host with the k3d kubeconfig as its `kubernetes` target, i.e. the
bastion-adjacent production shape in miniature. Sibling to `sim/` (the
gVisor-sandboxed single-target harness); same house conventions, different
substrate.

## How it works

`k3d/run.sh` creates one throwaway k3d cluster (single node, no agents),
then per scenario: arm → **verify the fault is real** (kubectl status
fields, not just that `apply` exited 0) → boot a real `opsclaw` daemon
against the cluster and assert detection (`sim/daemon-harness.sh`, shared
with `sim/run.sh` — see "What's wired today" below) → disarm → verify
clean. The cluster is deleted on every exit path.

Each scenario in `k3d/scenarios/<name>/` is three files:

- `arm.sh` — injects the fault against the cluster (`$K3D_SLOT` /
  `$K3D_CLUSTER` env vars, `KUBECONFIG` already pointed at the throwaway
  cluster), then **verifies the fault is real** (polls `kubectl get`/`describe`
  status fields — waiting reasons, restart counts, rollout conditions — never
  trusts its own exit code alone).
- `disarm.sh` — reverses the fault and verifies the cluster is clean again.
- `expected.json` — what a daemon pointed at this cluster should do. Same
  schema as `sim/`: `sim/expected.schema.json`.

## Running

```sh
k3d/run.sh                          # every scenario, one cluster, sequentially
k3d/run.sh crashloop                 # one scenario
k3d/run.sh crashloop cluster-death   # a subset
k3d/run.sh --keep                    # leave the cluster up after a pass (debugging)
```

Requires `k3d`, `kubectl`, and `docker` on `PATH` — `k3d/run.sh` fails fast
with a clear message if any are missing.

The cluster is named `opsclaw-k3d-run<PID>` (unique per invocation via the
shell's own `$$`, sharing the `opsclaw-k3d-` prefix every slot uses — see
`k3d_cluster_name` in `lib.sh`) so a run never collides with a leftover
cluster from a previous interrupted run, and the prefix lets the reap trap
sweep all of them regardless of exact suffix. The kubeconfig is written to a
private `mktemp -d` temp dir (`$K3D_RUN_TMPDIR/kubeconfig-<slot>.yaml`) and
is **never merged into `~/.kube/config`** — every `kubectl`/`helm` call in
this harness gets `--kubeconfig`/`KUBECONFIG` pointed explicitly at that
file, so a throwaway cluster can never become anyone's ambient context.

## Cleanup discipline

Exactly `sim/run.sh`'s trap discipline: `k3d/run.sh` traps `EXIT INT TERM` and
tears the cluster down on every exit path — normal completion, a `set -e`
abort mid-scenario, or a signal. `--keep` is the one explicit opt-out. On top
of the direct teardown, `k3d_reap_all` (in `lib.sh`) does a belt-and-braces
sweep for any other `opsclaw-k3d-*` cluster left behind by a previous
interrupted run, mirroring `sim`'s prefix-filter reap for containers. A
leaked k3d cluster is a harness bug of the same severity as a leaked sim
container: it's a full k3s server + containerd + load-balancer container left
running on the host indefinitely.

Resource use is capped per scenario the same way `sim/` caps its containers —
`node-pressure` sizes its OOM fault off a **24Mi pod memory limit**, not a
percentage of host RAM, so the fault is bounded regardless of how much memory
the dev host actually has.

## What's wired today

**Fault injection layer:** cluster create/delete, all five scenarios'
arm/disarm round-trip with real verification (a genuine `CrashLoopBackOff`
waiting reason, a genuine `OOMKilled` lastState from a real cgroup limit, a
genuine `ProgressDeadlineExceeded` + `ImagePullBackOff` pair, a genuinely
unreachable API server after `k3d cluster stop` corroborated against the
docker container state, a genuinely `Ready` healthy Deployment for the
silent control).

**Daemon-detection assertion (DESIGN.md §6, `sim/daemon-harness.sh` — shared
with `sim/run.sh`, see `sim/README.md`'s "What's wired today" for the full
breakdown):**
`k3d/run.sh` boots a REAL `opsclaw` daemon per scenario, under a scrubbed,
non-inherited environment, against a throwaway `OPSCLAW_HOME` + generated
`config.toml` declaring the cluster as a `kubernetes` target (credential =
the throwaway kubeconfig path `k3d_kubeconfig` already writes — never
`~/.kube/config`). One daemon PER scenario, not one shared across the whole
run, even though every scenario shares the one cluster: a shared daemon
would carry incidents opened by a previous scenario into the next one's
assertions.

Deterministic tier (always runs): doctor's probe reaches the target through
the same executor construction path the daemon boots with, a scan tick
fires, the daemon survives the armed fault, and (for `must_notify=false`)
the incidents table stays empty. Live tier
(`OPSCLAW_LIVE_EVALS=1`+`OPENROUTER_API_KEY`, same gate as
`tests/evals.rs`): exactly one incident (or zero) across two observed ticks,
severity matching `expected.json`. Everything the deterministic tier can't
prove is printed as an explicit `SKIPPED` line.

**cluster-death is the one exception to "doctor must reach the target":**
its entire premise is the target being unreachable (DESIGN.md §6:
"untestable if the agent lived inside it"), so `run_one_scenario` passes
`expect_reachable=false` for it — the harness asserts doctor reports
UNREACHABLE, which is the correct positive check for that one fault class.

## Scenarios

| Scenario | Fault | Verification |
|---|---|---|
| `crashloop` | busybox pod exits 1 on every start | polls until `containerStatuses[0].state.waiting.reason == CrashLoopBackOff` and `restartCount >= 1` |
| `node-pressure` | pod allocates memory past a 24Mi limit | polls until `lastState.terminated.reason == OOMKilled` |
| `failed-rollout` | Deployment pinned to a nonexistent image tag, `progressDeadlineSeconds: 20` | polls until pod is `ImagePullBackOff`/`ErrImagePull` **and** the Deployment's `Progressing` condition reports `ProgressDeadlineExceeded` |
| `cluster-death` | `k3d cluster stop` (not delete) | confirms the API server rejects a `--request-timeout=5s` request **and** the k3d server container is actually stopped (docker-level corroboration); disarm restarts and confirms node `Ready` again |
| `silent-baseline` | none — genuinely healthy single-replica Deployment | waits for `kubectl rollout status` to actually finish and `availableReplicas >= 1`; the anti-spam/false-positive control |

## Helm smoke

`k3d/helm-smoke.sh` is a separate script (not a `scenarios/` entry — it
doesn't have a meaningful "disarm", it's a one-shot render-and-check) that
installs `deploy/helm/` into its own throwaway k3d cluster with a placeholder
image and asserts the rendered objects exist and the PVC binds. See that
script's header comment for what it does and does not assert.

## Adding a scenario

1. `mkdir k3d/scenarios/<name>`
2. Write `arm.sh` / `disarm.sh` — idempotent, self-contained, verify the
   fault via real `kubectl` status fields (not just the apply's exit code).
3. Write `expected.json` against `sim/expected.schema.json` (shared schema —
   `fq_target` still uses the `project::env::target` form, just with a
   k3d-flavoured target name).
4. `chmod +x arm.sh disarm.sh`.
5. `k3d/run.sh <name>` to validate in isolation before running the full suite.
