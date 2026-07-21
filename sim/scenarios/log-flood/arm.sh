#!/usr/bin/env bash
# log-flood — crank the log-emitter's line RATE way up (many small lines/sec)
# without growing individual line size. Exercises noisy-volume detection
# distinct from file-size growth (see logfile-growth, its sibling scenario).
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" sh -c "echo 200 > /run/opsclaw-sim/log-rate-hz"
sleep 5

lines_before="$(docker exec "$SIM_CONTAINER" wc -l /var/log/opsclaw-sim/app.log | awk '{print $1}')"
sleep 3
lines_after="$(docker exec "$SIM_CONTAINER" wc -l /var/log/opsclaw-sim/app.log | awk '{print $1}')"
delta=$(( lines_after - lines_before ))
echo "log-flood: armed, +${delta} lines in 3s (rate-hz=200)"

if [ "$delta" -lt 100 ]; then
    echo "log-flood: FAIL — expected high line rate, saw only ${delta} lines/3s" >&2
    exit 1
fi
