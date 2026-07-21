#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" pkill -x stress-ng 2>/dev/null || true
sleep 1
if docker exec "$SIM_CONTAINER" pgrep -x stress-ng >/dev/null 2>&1; then
    echo "cpu-4way: FAIL — stress-ng still running after disarm" >&2
    exit 1
fi
echo "cpu-4way: disarmed, target clean"
