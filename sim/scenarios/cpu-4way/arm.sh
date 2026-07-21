#!/usr/bin/env bash
# cpu-4way — 4-way CPU saturation. Ported as a REQUIREMENT (brief §9: "the
# agent currently misses 4-way CPU saturation") — this scenario exists
# specifically to keep that regression from coming back.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" pkill -x stress-ng 2>/dev/null || true
docker exec -d "$SIM_CONTAINER" stress-ng --cpu 4 --cpu-load 95 --timeout 0

sleep 3
nproc="$(docker exec "$SIM_CONTAINER" nproc)"
load="$(docker exec "$SIM_CONTAINER" sh -c "cat /proc/loadavg | cut -d' ' -f1")"
echo "cpu-4way: armed, nproc=${nproc} 1-min loadavg=${load}"

workers="$(docker exec "$SIM_CONTAINER" sh -c "pgrep -x stress-ng | wc -l")"
if [ "$workers" -lt 1 ]; then
    echo "cpu-4way: FAIL — stress-ng is not running after arm" >&2
    exit 1
fi
