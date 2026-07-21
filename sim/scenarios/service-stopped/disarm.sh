#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" supervisorctl start fake-web
sleep 1

status="$(docker exec "$SIM_CONTAINER" supervisorctl status fake-web | awk '{print $2}' || true)"
echo "service-stopped: disarmed, fake-web status=${status}"

if [ "$status" != "RUNNING" ]; then
    echo "service-stopped: FAIL — expected RUNNING, got ${status}" >&2
    exit 1
fi
