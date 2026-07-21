#!/usr/bin/env bash
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

NAME=opsclaw-failed-rollout

k3d_kubectl "$K3D_SLOT" delete deployment "$NAME" --ignore-not-found --wait=true --timeout=60s >/dev/null

if k3d_kubectl "$K3D_SLOT" get deployment "$NAME" >/dev/null 2>&1; then
    echo "failed-rollout: FAIL — deployment ${NAME} still present after delete" >&2
    exit 1
fi
# Deleting the Deployment cascades to its ReplicaSets/Pods via GC, but that GC
# is asynchronous — confirm the pods are actually gone too before declaring
# clean, same "verify, don't trust the delete's exit code" discipline as arm.
waited=0
while k3d_kubectl "$K3D_SLOT" get pods -l "app=${NAME}" --no-headers 2>/dev/null | grep -q .; do
    waited=$((waited + 1))
    [ "$waited" -ge 30 ] && {
        echo "failed-rollout: FAIL — pods for ${NAME} still present 30s after deployment delete" >&2
        exit 1
    }
    sleep 1
done
echo "failed-rollout: disarmed, deployment and pods gone"
