#!/usr/bin/env bash
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

NAME=opsclaw-node-pressure

k3d_kubectl "$K3D_SLOT" delete pod "$NAME" --ignore-not-found --wait=true --timeout=60s >/dev/null

if k3d_kubectl "$K3D_SLOT" get pod "$NAME" >/dev/null 2>&1; then
    echo "node-pressure: FAIL — pod ${NAME} still present after delete" >&2
    exit 1
fi
echo "node-pressure: disarmed, pod gone"
