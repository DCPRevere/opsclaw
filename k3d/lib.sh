#!/usr/bin/env bash
# k3d/lib.sh — shared helpers for k3d/run.sh and scenario arm/disarm
# scripts. Sourced, not executed; every function assumes `set -euo pipefail`
# is already active in the caller.
#
# Mirrors sim/lib.sh's conventions (slot-scoped naming, verify-don't-trust,
# reap-on-every-exit) for the kubernetes Tier 2 layer (DESIGN.md §6 "Tier 2,
# kubernetes"): a throwaway k3d cluster stands in for the bastion-adjacent
# production shape in miniature.

K3D_NAME_PREFIX="opsclaw-k3d-"
K3D_NAMESPACE="${K3D_NAMESPACE:-default}"

# The daemon-detection assertion (brief §9) — shared with sim/lib.sh. Lives
# under sim/ rather than a third top-level dir because sim/expected.schema.json
# is already the cross-shared schema both harnesses validate scenarios
# against (see k3d/README.md); this is the same relationship for the
# daemon-boot/assertion helpers.
# shellcheck source=sim/daemon-harness.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../sim" && pwd)/daemon-harness.sh"

# k3d_cluster_name SLOT
# Names are slot-scoped so scenarios can (in principle) run in isolated
# clusters; run.sh itself runs scenarios sequentially against one cluster per
# invocation (a fresh k3d cluster is expensive enough — tens of seconds — that
# per-scenario clusters would dominate runtime), but the naming still avoids
# collision with any other opsclaw-k3d-* cluster a parallel invocation left.
k3d_cluster_name() {
    local slot="${1:?slot required}"
    echo "${K3D_NAME_PREFIX}${slot}"
}

k3d_log() {
    printf '[k3d] %s\n' "$*" >&2
}

k3d_die() {
    printf '[k3d] ERROR: %s\n' "$*" >&2
    exit 1
}

# k3d_require_tools
# Fail fast with a clear message rather than a confusing failure three steps
# in.
k3d_require_tools() {
    local missing=()
    for bin in k3d kubectl docker; do
        command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        k3d_die "required tool(s) not found on PATH: ${missing[*]}"
    fi
}

# k3d_kubeconfig SLOT
# Path to this slot's kubeconfig inside the run's private temp dir
# ($K3D_RUN_TMPDIR, set by run.sh). NEVER merged into ~/.kube/config — every
# kubectl/helm invocation in this harness passes --kubeconfig explicitly (or
# has KUBECONFIG exported to this path) so a throwaway cluster can never
# become the operator's ambient context.
k3d_kubeconfig() {
    local slot="${1:?slot required}"
    : "${K3D_RUN_TMPDIR:?K3D_RUN_TMPDIR must be set by the caller (run.sh)}"
    echo "${K3D_RUN_TMPDIR}/kubeconfig-${slot}.yaml"
}

# k3d_kubectl SLOT -- ARGS...
k3d_kubectl() {
    local slot="$1"; shift
    kubectl --kubeconfig "$(k3d_kubeconfig "$slot")" -n "$K3D_NAMESPACE" "$@"
}

# k3d_create_cluster SLOT
# Single-node (server only, no agents) cluster — the fault classes here
# (crashloop, pressure, bad rollout, cluster death) don't need multi-node
# scheduling, and a second node just doubles create/delete time. Kubeconfig
# written to the run's private temp dir only (--kubeconfig-update-default=false,
# and k3d's default merge-into-~/.kube/config is skipped entirely by using
# --kubeconfig-switch-context=false plus writing via `k3d kubeconfig get`
# rather than letting `cluster create` touch the default file at all).
k3d_create_cluster() {
    local slot="$1" name kubeconfig
    name="$(k3d_cluster_name "$slot")"
    kubeconfig="$(k3d_kubeconfig "$slot")"

    k3d_log "creating cluster ${name}"
    k3d cluster create "$name" \
        --servers 1 --agents 0 \
        --no-lb=false \
        --wait --timeout 120s \
        --kubeconfig-update-default=false \
        --kubeconfig-switch-context=false \
        >&2

    k3d kubeconfig get "$name" > "$kubeconfig"
    chmod 600 "$kubeconfig"

    k3d_log "waiting for node Ready in ${name}"
    local waited=0
    while ! kubectl --kubeconfig "$kubeconfig" get nodes --no-headers 2>/dev/null \
            | awk '{print $2}' | grep -qx Ready; do
        waited=$((waited + 1))
        [ "$waited" -ge 60 ] && k3d_die "node did not become Ready in ${name} within 60s"
        sleep 1
    done
}

# k3d_delete_cluster SLOT
# Idempotent — safe to call on a cluster that's already gone (disarm paths,
# double-reap on the trap).
k3d_delete_cluster() {
    local slot="$1" name
    name="$(k3d_cluster_name "$slot")"
    k3d cluster delete "$name" >&2 2>&1 || true
}

# k3d_reap_all
# Belt-and-braces reap: delete every opsclaw-k3d-* cluster regardless of
# which slot(s) were in flight, on ANY exit path (normal, failure, signal).
# A leaked cluster is a harness bug of the same severity sim/ assigns a
# leaked container — it is a full k3s server + containerd + node container
# left running on the host indefinitely.
k3d_reap_all() {
    local names
    names="$(k3d cluster list -o json 2>/dev/null | grep -o '"name":"'"${K3D_NAME_PREFIX}"'[^"]*"' | cut -d'"' -f4 || true)"
    [ -z "$names" ] && return 0
    local n
    for n in $names; do
        k3d_log "reaping leftover cluster ${n}"
        k3d cluster delete "$n" >&2 2>&1 || true
    done
}

# k3d_wait_for_pod_condition SLOT SELECTOR CONDITION TIMEOUT_SECS
# Thin wrapper over `kubectl wait`, non-fatal on timeout (returns the exit
# code so callers can produce a scenario-specific failure message rather than
# a bare kubectl error).
k3d_wait_for_pod_condition() {
    local slot="$1" selector="$2" condition="$3" timeout="${4:-60}"
    k3d_kubectl "$slot" wait pod -l "$selector" \
        --for="condition=${condition}" --timeout="${timeout}s" 2>&1
}
