#!/usr/bin/env bash
# k3d/helm-smoke.sh — installs deploy/helm/ into its own throwaway k3d
# cluster with a placeholder image and asserts the packaging is honest
# (DESIGN.md §6: "One smoke scenario installs the Helm chart in-cluster to
# keep that packaging honest").
#
# This is deliberately NOT a scenarios/ entry: it doesn't have a meaningful
# arm/disarm fault cycle, it's a one-shot render-install-assert-teardown.
# It reuses k3d/lib.sh for cluster lifecycle so the cleanup discipline
# matches run.sh exactly (trap on every exit path, prefix-filter reap).
#
# What this asserts: the chart's objects actually render, install, and
# schedule correctly against a real API server — Deployment/PVC/Service/
# ConfigMap/RBAC/PriorityClass/PDB all present, the PVC actually BINDS (a
# real storage-class provisioning round-trip, not just "the YAML is valid"),
# and the pod is admitted and scheduled (not necessarily Running — a
# placeholder image is expected to fail to pull, since this harness has no
# real opsclaw image yet; see the Dockerfile note in deploy/Dockerfile).
#
# What this does NOT assert: that the daemon actually boots and serves
# /ready. That needs a real built-and-pushed image and belongs to a later
# wave once src/ produces one.
#
# Usage: k3d/helm-smoke.sh [--keep]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/lib.sh"

KEEP=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        --help|-h) sed -n '2,25p' "$0"; exit 0 ;;
        *) k3d_die "unknown argument: $arg" ;;
    esac
done

command -v helm >/dev/null 2>&1 || k3d_die "helm not found on PATH"
k3d_require_tools

K3D_RUN_TMPDIR="$(mktemp -d)"
export K3D_RUN_TMPDIR

SLOT="helmsmoke$$"
CLUSTER_NAME="$(k3d_cluster_name "$SLOT")"
RELEASE=opsclaw-smoke

_final_reap() {
    local rc=$?
    if [ "$KEEP" -ne 0 ]; then
        k3d_log "--keep set, leaving cluster ${CLUSTER_NAME} up (kubeconfig: $(k3d_kubeconfig "$SLOT"))"
        return "$rc"
    fi
    k3d_log "tearing down ${CLUSTER_NAME}"
    k3d_delete_cluster "$SLOT"
    k3d_reap_all
    rm -rf "$K3D_RUN_TMPDIR" 2>/dev/null || true
    return "$rc"
}
trap _final_reap EXIT INT TERM

k3d_create_cluster "$SLOT"

KUBECONFIG_PATH="$(k3d_kubeconfig "$SLOT")"

k3d_log "helm lint"
helm lint "${REPO_ROOT}/deploy/helm" --strict \
    --set deadmanUrl=https://hc-ping.com/opsclaw-k3d-smoke-test

k3d_log "helm install (placeholder image — expected to fail to pull; we assert on rendered objects, not Running)"
helm --kubeconfig "$KUBECONFIG_PATH" install "$RELEASE" "${REPO_ROOT}/deploy/helm" \
    --namespace "$K3D_NAMESPACE" \
    --set deadmanUrl=https://hc-ping.com/opsclaw-k3d-smoke-test \
    --set image.repository=busybox \
    --set image.tag=1.36 \
    --wait=false \
    --timeout 60s

fail=0

# The chart's fullname helper (_helpers.tpl) collapses to just the release
# name when the release name already contains the chart name ("opsclaw-smoke"
# contains "opsclaw") — standard Helm scaffold behaviour, not a bug here. Do
# not hardcode "<release>-opsclaw"; derive the same names the templates use.
FULLNAME="$RELEASE"

k3d_log "asserting core objects rendered and were accepted by the API server"
for kind_name in \
    "deployment/${FULLNAME}" \
    "configmap/${FULLNAME}-config" \
    "service/${FULLNAME}" \
    "serviceaccount/${FULLNAME}" \
    "persistentvolumeclaim/${FULLNAME}-data" \
    "poddisruptionbudget/${FULLNAME}" \
    "clusterrole/${FULLNAME}-reader" \
    "clusterrolebinding/${FULLNAME}-reader" \
    "priorityclass/${FULLNAME}-critical"
do
    if k3d_kubectl "$SLOT" get "$kind_name" >/dev/null 2>&1; then
        k3d_log "  OK: ${kind_name} exists"
    else
        k3d_log "  FAIL: ${kind_name} missing"
        fail=1
    fi
done

k3d_log "asserting the PVC actually BINDS (real storage-class provisioning, not just valid YAML)"
waited=0
phase=""
until [ "$waited" -ge 60 ]; do
    phase="$(k3d_kubectl "$SLOT" get pvc "${FULLNAME}-data" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [ "$phase" = "Bound" ] && break
    waited=$((waited + 2))
    sleep 2
done
if [ "$phase" = "Bound" ]; then
    k3d_log "  OK: PVC Bound"
else
    k3d_log "  FAIL: PVC never reached Bound (last phase: '${phase}')"
    k3d_kubectl "$SLOT" describe pvc "${FULLNAME}-data" >&2 || true
    fail=1
fi

k3d_log "asserting the pod was admitted and scheduled (not necessarily Running — placeholder image)"
waited=0
scheduled=""
until [ "$waited" -ge 60 ]; do
    scheduled="$(k3d_kubectl "$SLOT" get pods -l "app.kubernetes.io/instance=${RELEASE}" \
        -o jsonpath='{.items[0].status.conditions[?(@.type=="PodScheduled")].status}' 2>/dev/null || true)"
    [ "$scheduled" = "True" ] && break
    waited=$((waited + 2))
    sleep 2
done
if [ "$scheduled" = "True" ]; then
    k3d_log "  OK: pod PodScheduled=True"
else
    k3d_log "  FAIL: pod never reached PodScheduled=True"
    k3d_kubectl "$SLOT" get pods -l "app.kubernetes.io/instance=${RELEASE}" -o wide >&2 || true
    fail=1
fi

k3d_log "asserting priorityClassName was actually applied to the pod spec (not just requested)"
applied_pc="$(k3d_kubectl "$SLOT" get pods -l "app.kubernetes.io/instance=${RELEASE}" \
    -o jsonpath='{.items[0].spec.priorityClassName}' 2>/dev/null || true)"
if [ "$applied_pc" = "${FULLNAME}-critical" ]; then
    k3d_log "  OK: priorityClassName=${applied_pc}"
else
    k3d_log "  FAIL: pod priorityClassName is '${applied_pc}', expected ${FULLNAME}-critical"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    k3d_log "helm-smoke: PASS"
else
    k3d_log "helm-smoke: FAIL"
fi
exit "$fail"
