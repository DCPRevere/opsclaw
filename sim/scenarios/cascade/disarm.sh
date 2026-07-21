#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

# TERM first, escalate to KILL (see mem-pressure/disarm.sh — a vm stressor
# holding dirty pages dies slowly on TERM).
docker exec "$SIM_CONTAINER" pkill -x stress-ng 2>/dev/null || true
for _ in 1 2 3 4 5; do
    docker exec "$SIM_CONTAINER" pgrep -x stress-ng >/dev/null 2>&1 || break
    sleep 1
done
docker exec "$SIM_CONTAINER" pkill -9 -x stress-ng 2>/dev/null || true
docker exec "$SIM_CONTAINER" rm -f /run/opsclaw-sim/worker-crash-every
docker exec "$SIM_CONTAINER" supervisorctl start fake-web

sleep 2

mem_pct="$(docker exec "$SIM_CONTAINER" sh -c "free | awk '/Mem:/{printf \"%d\", \$3/\$2*100}'")"
web_status="$(docker exec "$SIM_CONTAINER" supervisorctl status fake-web | awk '{print $2}' || true)"

echo "cascade: disarmed — mem=${mem_pct}% fake-web=${web_status}"

ok=1
[ "$mem_pct" -lt 50 ] || ok=0
[ "$web_status" = "RUNNING" ] || ok=0

if [ "$ok" -ne 1 ]; then
    echo "cascade: FAIL — target did not return to clean state" >&2
    exit 1
fi
