#!/usr/bin/env bash
# cpu-single — saturate a single CPU worker via stress-ng, baked into the
# target image (sim/target.Dockerfile). Idempotent: killing any prior
# stress-ng before starting a fresh one.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" pkill -x stress-ng 2>/dev/null || true
docker exec -d "$SIM_CONTAINER" stress-ng --cpu 1 --cpu-load 95 --timeout 0

# Verify the fault is real: give the worker a moment to spin up, then check
# CPU actually pegged, rather than trusting stress-ng's own exit code.
sleep 3
load="$(docker exec "$SIM_CONTAINER" sh -c "cat /proc/loadavg | cut -d' ' -f1")"
echo "cpu-single: armed, 1-min loadavg=${load}"
docker exec "$SIM_CONTAINER" pgrep -x stress-ng >/dev/null || {
    echo "cpu-single: FAIL — stress-ng is not running after arm" >&2
    exit 1
}
