#!/usr/bin/env bash
# crashloop — deploy a pod whose container exits nonzero repeatedly, and
# verify kubelet actually reports CrashLoopBackOff (not just that our pod
# spec was accepted — environment scepticism, DESIGN.md §3: corroborate,
# never trust a single signal).
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

NAME=opsclaw-crashloop

k3d_kubectl "$K3D_SLOT" delete pod "$NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true

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
    - name: crasher
      image: busybox:1.36
      command: ["sh", "-c", "echo dying; sleep 1; exit 1"]
      resources:
        requests: {cpu: "10m", memory: "16Mi"}
        limits: {cpu: "50m", memory: "32Mi"}
EOF

echo "crashloop: pod applied, waiting for CrashLoopBackOff to actually appear"

waited=0
status=""
until [ "$waited" -ge 90 ]; do
    status="$(k3d_kubectl "$K3D_SLOT" get pod "$NAME" \
        -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)"
    [ "$status" = "CrashLoopBackOff" ] && break
    waited=$((waited + 3))
    sleep 3
done

echo "crashloop: armed, container waiting-reason=${status:-<none>}"

if [ "$status" != "CrashLoopBackOff" ]; then
    echo "crashloop: FAIL — pod ${NAME} never reached CrashLoopBackOff (last seen: '${status}')" >&2
    k3d_kubectl "$K3D_SLOT" get pod "$NAME" -o wide >&2 || true
    exit 1
fi

restarts="$(k3d_kubectl "$K3D_SLOT" get pod "$NAME" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)"
if [ "${restarts:-0}" -lt 1 ]; then
    echo "crashloop: FAIL — restartCount is ${restarts}, expected at least 1" >&2
    exit 1
fi
echo "crashloop: verified, restartCount=${restarts}"
