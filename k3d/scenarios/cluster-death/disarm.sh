#!/usr/bin/env bash
# disarm restarts the cluster and verifies it is genuinely Ready again
# (both the API server answering and a node in Ready state) — the run.sh
# orchestrator tears the cluster down unconditionally afterward regardless,
# but leaving a scenario mid-fault on a nonzero disarm would be a harness bug
# the same way a leaked container is (a "stopped forever" cluster is still a
# resource left behind if a later scenario or a human --keep run touches it).
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
: "${K3D_CLUSTER:?run via k3d/run.sh, or export K3D_CLUSTER=<cluster-name>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

echo "cluster-death: restarting cluster ${K3D_CLUSTER}"
k3d cluster start "$K3D_CLUSTER" --wait --timeout 120s >&2

echo "cluster-death: verifying node reaches Ready again"
waited=0
while ! k3d_kubectl "$K3D_SLOT" --request-timeout=5s get nodes --no-headers 2>/dev/null \
        | awk '{print $2}' | grep -qx Ready; do
    waited=$((waited + 1))
    [ "$waited" -ge 60 ] && {
        echo "cluster-death: FAIL — node did not return to Ready within 60s of restart" >&2
        exit 1
    }
    sleep 1
done
echo "cluster-death: disarmed, cluster Ready again"
