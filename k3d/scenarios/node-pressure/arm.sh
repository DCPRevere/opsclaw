#!/usr/bin/env bash
# node-pressure — a pod with a tight memory limit that allocates past it and
# gets OOMKilled by the kernel/kubelet. This is a real memory-pressure signal
# (OOMKilled + high restart count) without stressing the k3d node's actual
# available RAM: the container's cgroup limit is what triggers the kill, so
# the "pressure" is capped at 24Mi regardless of host memory (DESIGN.md §6:
# "keep resource use capped — never stress the host").
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

NAME=opsclaw-node-pressure

k3d_kubectl "$K3D_SLOT" delete pod "$NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true

# busybox allocates well past its 24Mi limit via a growing here-string held in
# a shell array — deterministic OOM without needing stress-ng in the image.
k3d_kubectl "$K3D_SLOT" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${NAME}
  labels:
    app: ${NAME}
spec:
  restartPolicy: Always
  containers:
    - name: memhog
      image: busybox:1.36
      command:
        - sh
        - -c
        - |
          echo "allocating past the memory limit"
          awk 'BEGIN {
            pad = "x"
            for (i = 0; i < 20; i++) pad = pad pad
            s = ""
            while (1) s = s pad
          }'
      resources:
        requests: {cpu: "10m", memory: "8Mi"}
        limits: {cpu: "100m", memory: "24Mi"}
EOF

echo "node-pressure: pod applied, waiting for a genuine OOMKilled status"

waited=0
reason=""
until [ "$waited" -ge 90 ]; do
    reason="$(k3d_kubectl "$K3D_SLOT" get pod "$NAME" \
        -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}' 2>/dev/null || true)"
    [ "$reason" = "OOMKilled" ] && break
    waited=$((waited + 3))
    sleep 3
done

echo "node-pressure: armed, lastState.terminated.reason=${reason:-<none>}"

if [ "$reason" != "OOMKilled" ]; then
    echo "node-pressure: FAIL — pod ${NAME} was never OOMKilled (last seen: '${reason}')" >&2
    k3d_kubectl "$K3D_SLOT" describe pod "$NAME" >&2 || true
    exit 1
fi
echo "node-pressure: verified"
