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
fields, not just that `apply` exited 0) → (today: stop here and report; see
TODO below) → disarm → verify clean. The cluster is deleted on every exit
path.

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

## What's wired today vs. TODO

**Working today:** cluster create/delete, all five scenarios' arm/disarm
round-trip with real verification (a genuine `CrashLoopBackOff` waiting
reason, a genuine `OOMKilled` lastState from a real cgroup limit, a genuine
`ProgressDeadlineExceeded` + `ImagePullBackOff` pair, a genuinely unreachable
API server after `k3d cluster stop` corroborated against the docker
container state, a genuinely `Ready` healthy Deployment for the silent
control).

**TODO (later wave — daemon sim-runner integration):** `k3d/run.sh` does not
yet point a live `opsclaw` daemon at the cluster and assert detection. The
wiring point is marked inline in `k3d/run.sh` with
`TODO(daemon-integration)`, immediately after arm and before disarm — the
same shape as the equivalent TODO in `sim/run.sh`. Once the daemon has a way
to load a `kubernetes` target pointed at the scenario's kubeconfig, that TODO
block becomes:

1. Configure/point the daemon at the scenario's `fq_target`.
2. Wait for (or force) a scan tick.
3. Assert `opsclaw_notify` was called exactly once when
   `expected.json.must_notify` is true (payload's `fault`/`severity`
   matching), or zero times when false.
4. Assert no further notify calls fire while the fault stays armed
   (anti-spam).

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
