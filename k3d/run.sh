#!/usr/bin/env bash
# k3d/run.sh — Tier 2 kubernetes fault-injection harness orchestrator
# (DESIGN.md §6 "Tier 2, kubernetes").
#
# Creates a throwaway k3d cluster (opsclaw on the host would point its
# `kubernetes` target at this cluster's kubeconfig — the bastion-adjacent
# production shape in miniature), runs each scenario's arm → verify → disarm
# → verify-clean cycle against it, and deletes the cluster on every exit path.
#
# What this script does NOT do yet: point a live opsclaw daemon at the
# cluster and assert it detected the fault via a structured notify call
# matching expected.json. That's the actual acceptance test (mirrors the
# sim/run.sh TODO) and needs the daemon's kubernetes-target + sim-runner
# integration, a later wave. Everything up to and including "the fault is
# really present in the cluster" is built and verified here today.
#
# Usage:
#   k3d/run.sh                     # every scenario, one cluster, sequentially
#   k3d/run.sh crashloop            # one scenario
#   k3d/run.sh crashloop cluster-death   # a subset
#   k3d/run.sh --keep               # leave the cluster up after a pass (debugging)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/lib.sh"

KEEP=0
SLOT_SUFFIX="$$"
SCENARIOS=()

for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        --help|-h)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *) SCENARIOS+=("$arg") ;;
    esac
done

if [ "${#SCENARIOS[@]}" -eq 0 ]; then
    while IFS= read -r -d '' dir; do
        SCENARIOS+=("$(basename "$dir")")
    done < <(find "${SCRIPT_DIR}/scenarios" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
fi

k3d_require_tools

# Private temp dir for kubeconfigs — never merged into ~/.kube/config (see
# k3d_kubeconfig in lib.sh). Reaped alongside the cluster on every exit path.
K3D_RUN_TMPDIR="$(mktemp -d)"
export K3D_RUN_TMPDIR

SLOT="run${SLOT_SUFFIX}"
CLUSTER_NAME="$(k3d_cluster_name "$SLOT")"

# Reap on EVERY exit path — normal, a `set -e` abort mid-scenario, or a
# signal. Exactly sim/run.sh's discipline: a leaked k3d cluster is a full k3s
# server + containerd + load balancer container left running on the host, and
# a Ctrl-C'd run is exactly how that happens if teardown isn't trap-driven.
_final_reap() {
    local rc=$?
    if [ "$KEEP" -ne 0 ]; then
        k3d_log "--keep set, leaving cluster ${CLUSTER_NAME} up (kubeconfig: $(k3d_kubeconfig "$SLOT"))"
        return "$rc"
    fi
    k3d_log "tearing down ${CLUSTER_NAME}"
    k3d_delete_cluster "$SLOT"
    # Belt-and-braces: reap any other opsclaw-k3d-* cluster a previous
    # interrupted run left behind, same as sim's prefix-filter reap.
    k3d_reap_all
    rm -rf "$K3D_RUN_TMPDIR" 2>/dev/null || true
    return "$rc"
}
trap _final_reap EXIT INT TERM

k3d_create_cluster "$SLOT"

# run_one_scenario NAME
run_one_scenario() {
    local scenario="$1"
    local sdir="${SCRIPT_DIR}/scenarios/${scenario}"
    local rc=0

    [ -d "$sdir" ] || k3d_die "no such scenario: ${scenario} (looked in ${sdir})"
    [ -x "${sdir}/arm.sh" ] || k3d_die "${scenario}: arm.sh missing or not executable"
    [ -x "${sdir}/disarm.sh" ] || k3d_die "${scenario}: disarm.sh missing or not executable"
    [ -f "${sdir}/expected.json" ] || k3d_die "${scenario}: expected.json missing"

    k3d_log "[${scenario}] arming"
    if ! K3D_SLOT="$SLOT" K3D_CLUSTER="$CLUSTER_NAME" K3D_RUN_TMPDIR="$K3D_RUN_TMPDIR" \
            KUBECONFIG="$(k3d_kubeconfig "$SLOT")" "${sdir}/arm.sh"; then
        k3d_log "[${scenario}] FAIL: arm.sh exited nonzero"
        rc=1
    fi

    if [ "$rc" -eq 0 ]; then
        k3d_log "[${scenario}] fault armed — TODO(daemon-integration): point a live opsclaw"
        k3d_log "  daemon at this cluster (kubeconfig $(k3d_kubeconfig "$SLOT")) as its"
        k3d_log "  kubernetes target using the scenario's fq_target from expected.json, wait"
        k3d_log "  for a detection tick, and assert:"
        k3d_log "    - opsclaw_notify called exactly once (or zero times if must_notify=false)"
        k3d_log "    - the notify payload's fault/severity match expected.json"
        k3d_log "    - no further notify calls fire while the fault stays armed (anti-spam)"
        k3d_log "  This is the actual DESIGN.md §6 acceptance assertion; everything above and"
        k3d_log "  below it (cluster boot, fault is verifiably real, clean disarm) is wired"
        k3d_log "  and passing today without a daemon."
    fi

    k3d_log "[${scenario}] disarming"
    if ! K3D_SLOT="$SLOT" K3D_CLUSTER="$CLUSTER_NAME" K3D_RUN_TMPDIR="$K3D_RUN_TMPDIR" \
            KUBECONFIG="$(k3d_kubeconfig "$SLOT")" "${sdir}/disarm.sh"; then
        k3d_log "[${scenario}] WARN: disarm.sh exited nonzero"
        rc=1
    fi

    if [ "$rc" -eq 0 ]; then
        k3d_log "[${scenario}] PASS"
    else
        k3d_log "[${scenario}] FAIL"
    fi
    return "$rc"
}

overall_rc=0
for scenario in "${SCENARIOS[@]}"; do
    run_one_scenario "$scenario" || overall_rc=1
done

if [ "$overall_rc" -eq 0 ]; then
    k3d_log "all scenarios passed (fault-injection layer only — see TODO above for daemon assertion)"
else
    k3d_log "one or more scenarios FAILED"
fi
exit "$overall_rc"
