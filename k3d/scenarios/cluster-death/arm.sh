#!/usr/bin/env bash
# cluster-death — stop the whole k3d cluster (`k3d cluster stop`, not
# delete) and verify the API server is genuinely unreachable, not just that
# the stop command exited 0. This is the one fault class that can only be
# tested from OUTSIDE the cluster (DESIGN.md §6: "untestable if the agent
# lived inside it") — opsclaw must be able to report a dead cluster while
# staying reachable itself, which is exactly why it runs adjacent, never
# in-cluster-only.
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
: "${K3D_CLUSTER:?run via k3d/run.sh, or export K3D_CLUSTER=<cluster-name>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

echo "cluster-death: stopping cluster ${K3D_CLUSTER}"
k3d cluster stop "$K3D_CLUSTER" >&2

echo "cluster-death: verifying the API server is genuinely unreachable"

# A short client-side timeout: this must fail fast and definitively, not hang
# for kubectl's default (long) dial timeout.
if k3d_kubectl "$K3D_SLOT" --request-timeout=5s get --raw /healthz >/dev/null 2>&1; then
    echo "cluster-death: FAIL — API server still answered /healthz after cluster stop" >&2
    exit 1
fi

# Corroborate via docker too (environment scepticism — don't trust a single
# signal): the k3d server container itself must actually be stopped, not just
# refusing one request for an unrelated reason.
server_state="$(docker inspect -f '{{.State.Running}}' "k3d-${K3D_CLUSTER}-server-0" 2>/dev/null || echo unknown)"
echo "cluster-death: armed, api-server-reachable=no server-container-running=${server_state}"

if [ "$server_state" != "false" ]; then
    echo "cluster-death: FAIL — expected k3d-${K3D_CLUSTER}-server-0 to be stopped, docker reports Running=${server_state}" >&2
    exit 1
fi
echo "cluster-death: verified — API unreachable and server container confirmed stopped"
