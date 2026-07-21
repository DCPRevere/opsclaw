#!/usr/bin/env bash
# cascade — composite fault: memory pressure driving fake-worker into a
# crash/restart loop, plus the stopped fake-web service, arriving together.
# This is the anti-spam stress case (brief §6/§9): a single underlying
# incident (or a correlated cluster of them) must not fan out into a
# notify-per-symptom flood — the daemon should either correlate into one
# incident or, at minimum, not spam one-notify-per-signal.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" pkill -x stress-ng 2>/dev/null || true
docker exec -d "$SIM_CONTAINER" stress-ng --vm 2 --vm-bytes 80% --vm-keep --timeout 0
docker exec "$SIM_CONTAINER" sh -c "echo 5 > /run/opsclaw-sim/worker-crash-every"
docker exec "$SIM_CONTAINER" supervisorctl stop fake-web

sleep 4

mem_pct="$(docker exec "$SIM_CONTAINER" sh -c "free | awk '/Mem:/{printf \"%d\", \$3/\$2*100}'")"
# || true on status reads below: supervisorctl status exits nonzero when any
# listed process is not RUNNING (here: the STOPPED state we are asserting),
# which would trip set -e before the check runs.
web_status="$(docker exec "$SIM_CONTAINER" supervisorctl status fake-web | awk '{print $2}' || true)"
worker_up="$(docker exec "$SIM_CONTAINER" pgrep -f fake-worker.sh | wc -l)"

echo "cascade: armed — mem=${mem_pct}% fake-web=${web_status} worker-processes=${worker_up}"

ok=1
[ "$mem_pct" -ge 50 ] || ok=0
[ "$web_status" = "STOPPED" ] || ok=0
[ "$worker_up" -ge 1 ] || ok=0

if [ "$ok" -ne 1 ]; then
    echo "cascade: FAIL — one or more component faults did not arm correctly" >&2
    exit 1
fi
