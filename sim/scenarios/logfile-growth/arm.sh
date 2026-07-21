#!/usr/bin/env bash
# logfile-growth — REQUIREMENT (brief §9: "the agent currently misses
# ... log-file growth"). Grows app.log's on-disk SIZE quickly via large line
# payloads at a modest rate, distinct from log-flood's small/fast lines —
# this exercises detecting file-size growth trajectory, not line noise.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" sh -c "echo 5 > /run/opsclaw-sim/log-rate-hz"
docker exec "$SIM_CONTAINER" sh -c "echo 65536 > /run/opsclaw-sim/log-line-bytes"

size_before="$(docker exec "$SIM_CONTAINER" stat -c%s /var/log/opsclaw-sim/app.log)"
sleep 5
size_after="$(docker exec "$SIM_CONTAINER" stat -c%s /var/log/opsclaw-sim/app.log)"
delta=$(( size_after - size_before ))
echo "logfile-growth: armed, app.log grew ${delta} bytes in 5s"

if [ "$delta" -lt 100000 ]; then
    echo "logfile-growth: FAIL — expected rapid file growth, saw only ${delta} bytes/5s" >&2
    exit 1
fi
