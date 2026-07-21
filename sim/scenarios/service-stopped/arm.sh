#!/usr/bin/env bash
# service-stopped — cleanly stop fake-web via supervisorctl (the
# systemd-shim, target.Dockerfile) and set autostart=false-equivalent by
# holding it stopped, standing in for `systemctl stop <unit>` /
# `docker stop <container>` style single-service outages.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" supervisorctl stop fake-web
sleep 1

# || true: supervisorctl status exits nonzero when the process is STOPPED —
# exactly the state we're asserting — which would trip set -e before the check.
status="$(docker exec "$SIM_CONTAINER" supervisorctl status fake-web | awk '{print $2}' || true)"
echo "service-stopped: armed, fake-web status=${status}"

if [ "$status" != "STOPPED" ]; then
    echo "service-stopped: FAIL — expected STOPPED, got ${status}" >&2
    exit 1
fi
