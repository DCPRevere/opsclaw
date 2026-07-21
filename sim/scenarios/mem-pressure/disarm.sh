#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

# TERM first, escalate to KILL: a vm stressor holding hundreds of dirty MB
# can take several seconds to exit on TERM; disarm must be deterministic.
docker exec "$SIM_CONTAINER" pkill -x stress-ng 2>/dev/null || true
for _ in 1 2 3 4 5; do
    docker exec "$SIM_CONTAINER" pgrep -x stress-ng >/dev/null 2>&1 || break
    sleep 1
done
docker exec "$SIM_CONTAINER" pkill -9 -x stress-ng 2>/dev/null || true
sleep 1

if docker exec "$SIM_CONTAINER" pgrep -x stress-ng >/dev/null 2>&1; then
    echo "mem-pressure: FAIL — stress-ng still running after disarm" >&2
    exit 1
fi
echo "mem-pressure: disarmed, target clean"
