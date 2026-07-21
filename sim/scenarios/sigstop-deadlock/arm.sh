#!/usr/bin/env bash
# sigstop-deadlock — SIGSTOP the fake-worker process. It stays resident (a
# normal `ps`/liveness check sees it as "running") but is fully wedged: no
# forward progress, no CPU use, no crash for supervisord to notice and
# restart. This exercises the deadlock-vs-crash distinction — a naive
# process-up check reports healthy while the service is dead in the water.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

pid="$(docker exec "$SIM_CONTAINER" pgrep -f fake-worker.sh | head -1)"
[ -n "$pid" ] || { echo "sigstop-deadlock: FAIL — fake-worker not running" >&2; exit 1; }

docker exec "$SIM_CONTAINER" kill -STOP "$pid"
sleep 1

state="$(docker exec "$SIM_CONTAINER" sh -c "awk '/^State:/{print \$2}' /proc/${pid}/status")"
echo "sigstop-deadlock: armed, fake-worker pid=${pid} state=${state}"

if [ "$state" != "T" ]; then
    echo "sigstop-deadlock: FAIL — expected state T (stopped), got ${state}" >&2
    exit 1
fi
