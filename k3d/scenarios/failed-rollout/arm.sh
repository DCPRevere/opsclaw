#!/usr/bin/env bash
# failed-rollout — a Deployment pinned to a nonexistent image tag. Verifies
# the rollout is genuinely stuck: ImagePullBackOff on the pod AND the
# Deployment's Progressing condition reporting ProgressDeadlineExceeded, not
# just that `kubectl apply` succeeded (applying a bad spec always succeeds —
# the fault is in what happens after).
set -euo pipefail
: "${K3D_SLOT:?run via k3d/run.sh, or export K3D_SLOT=<slot>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

NAME=opsclaw-failed-rollout

k3d_kubectl "$K3D_SLOT" delete deployment "$NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true

# progressDeadlineSeconds set low (20s) so ProgressDeadlineExceeded fires
# quickly in a test run rather than the default 600s.
k3d_kubectl "$K3D_SLOT" apply -f - <<EOF >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${NAME}
  labels:
    app: ${NAME}
spec:
  replicas: 1
  progressDeadlineSeconds: 20
  selector:
    matchLabels: {app: ${NAME}}
  template:
    metadata:
      labels: {app: ${NAME}}
    spec:
      containers:
        - name: app
          image: busybox:this-tag-does-not-exist-opsclaw-test
          command: ["sh", "-c", "sleep 3600"]
          resources:
            requests: {cpu: "10m", memory: "16Mi"}
            limits: {cpu: "50m", memory: "32Mi"}
EOF

echo "failed-rollout: deployment applied, waiting for a genuinely stuck rollout"

waited=0
pull_reason=""
progressing=""
until [ "$waited" -ge 90 ]; do
    pull_reason="$(k3d_kubectl "$K3D_SLOT" get pods -l "app=${NAME}" \
        -o jsonpath='{.items[0].status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)"
    progressing="$(k3d_kubectl "$K3D_SLOT" get deployment "$NAME" \
        -o jsonpath='{.status.conditions[?(@.type=="Progressing")].reason}' 2>/dev/null || true)"

    is_pull_stuck=0
    case "$pull_reason" in
        ImagePullBackOff|ErrImagePull) is_pull_stuck=1 ;;
    esac

    if [ "$is_pull_stuck" -eq 1 ] && [ "$progressing" = "ProgressDeadlineExceeded" ]; then
        break
    fi
    waited=$((waited + 3))
    sleep 3
done

echo "failed-rollout: armed, pull_reason=${pull_reason:-<none>} progressing_reason=${progressing:-<none>}"

case "$pull_reason" in
    ImagePullBackOff|ErrImagePull) ;;
    *)
        echo "failed-rollout: FAIL — pod never reached ImagePullBackOff/ErrImagePull (got '${pull_reason}')" >&2
        exit 1
        ;;
esac
if [ "$progressing" != "ProgressDeadlineExceeded" ]; then
    echo "failed-rollout: FAIL — Deployment Progressing condition never reached ProgressDeadlineExceeded (got '${progressing}')" >&2
    k3d_kubectl "$K3D_SLOT" describe deployment "$NAME" >&2 || true
    exit 1
fi
echo "failed-rollout: verified"
