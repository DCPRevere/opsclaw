#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

pids="$(docker exec "$SIM_CONTAINER" pgrep -f fake-worker.sh || true)"
for pid in $pids; do
    docker exec "$SIM_CONTAINER" kill -CONT "$pid" 2>/dev/null || true
done
sleep 1

still_stopped=0
for pid in $pids; do
    state="$(docker exec "$SIM_CONTAINER" sh -c "awk '/^State:/{print \$2}' /proc/${pid}/status 2>/dev/null" || echo gone)"
    if [ "$state" = "T" ]; then
        still_stopped=1
    fi
done

if [ "$still_stopped" -eq 1 ]; then
    echo "sigstop-deadlock: FAIL — a fake-worker process is still stopped after disarm" >&2
    exit 1
fi
echo "sigstop-deadlock: disarmed, fake-worker resumed"
