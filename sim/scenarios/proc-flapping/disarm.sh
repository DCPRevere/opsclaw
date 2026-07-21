#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" rm -f /run/opsclaw-sim/worker-crash-every
sleep 1

pid1="$(docker exec "$SIM_CONTAINER" pgrep -f fake-worker.sh | head -1)"
sleep 6
pid2="$(docker exec "$SIM_CONTAINER" pgrep -f fake-worker.sh | head -1)"

if [ "$pid1" != "$pid2" ] || [ -z "$pid2" ]; then
    echo "proc-flapping: FAIL — worker still restarting after disarm" >&2
    exit 1
fi
echo "proc-flapping: disarmed, worker stable at pid ${pid2}"
