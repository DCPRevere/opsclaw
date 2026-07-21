#!/usr/bin/env bash
# silent-baseline — deploy a genuinely healthy Deployment and verify it
# actually reaches Ready, so "the daemon stayed silent" is a claim about a
# real healthy cluster, not a claim about an empty one (an empty cluster
# would trivially produce no faults; that's not the control this scenario
# means to be — mirrors sim/scenarios/silent-baseline's role as the
# anti-spam / false-positive control, DESIGN.md §6).
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

NAME=opsclaw-silent-baseline

k3d_kubectl "$K3D_SLOT" delete deployment "$NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true

k3d_kubectl "$K3D_SLOT" apply -f - <<EOF >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${NAME}
  labels:
    app: ${NAME}
spec:
  replicas: 1
  selector:
    matchLabels: {app: ${NAME}}
  template:
    metadata:
      labels: {app: ${NAME}}
    spec:
      containers:
        - name: app
          image: busybox:1.36
          command: ["sh", "-c", "while true; do sleep 3600; done"]
          resources:
            requests: {cpu: "10m", memory: "16Mi"}
            limits: {cpu: "50m", memory: "32Mi"}
EOF

echo "silent-baseline: deployment applied, waiting for genuine Ready"

if ! k3d_kubectl "$K3D_SLOT" rollout status deployment "$NAME" --timeout=60s >&2; then
    echo "silent-baseline: FAIL — deployment ${NAME} never became Ready" >&2
    k3d_kubectl "$K3D_SLOT" describe deployment "$NAME" >&2 || true
    exit 1
fi

available="$(k3d_kubectl "$K3D_SLOT" get deployment "$NAME" -o jsonpath='{.status.availableReplicas}')"
echo "silent-baseline: armed, availableReplicas=${available}"
if [ "${available:-0}" -lt 1 ]; then
    echo "silent-baseline: FAIL — availableReplicas is ${available}, expected >= 1" >&2
    exit 1
fi
echo "silent-baseline: verified healthy"
