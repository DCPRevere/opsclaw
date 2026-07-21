#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" rm -f /run/opsclaw-sim/log-rate-hz /run/opsclaw-sim/log-line-bytes
docker exec "$SIM_CONTAINER" sh -c "truncate -s 0 /var/log/opsclaw-sim/app.log || true"
sleep 1
echo "logfile-growth: disarmed, controls removed and app.log truncated"
