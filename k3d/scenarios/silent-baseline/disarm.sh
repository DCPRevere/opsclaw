#!/usr/bin/env bash
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

NAME=opsclaw-silent-baseline

k3d_kubectl "$K3D_SLOT" delete deployment "$NAME" --ignore-not-found --wait=true --timeout=60s >/dev/null

if k3d_kubectl "$K3D_SLOT" get deployment "$NAME" >/dev/null 2>&1; then
    echo "silent-baseline: FAIL — deployment ${NAME} still present after delete" >&2
    exit 1
fi
echo "silent-baseline: disarmed, deployment gone"
