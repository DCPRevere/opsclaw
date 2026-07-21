#!/usr/bin/env bash
# sim/fixtures/fake-worker.sh — stand-in background worker service.
# Normally just idles (heartbeat to its own log). proc-flapping scenario
# writes a nonzero exit code request to /run/opsclaw-sim/worker-crash-every
# (seconds) so this script exits on that cadence and supervisord's
# autorestart produces real, observable restart churn.
set -euo pipefail

CRASH_CTL=/run/opsclaw-sim/worker-crash-every
START=$(date +%s)

echo "fake-worker: starting pid $$"

while true; do
    sleep 1
    now=$(date +%s)
    elapsed=$((now - START))

    if [ -f "$CRASH_CTL" ]; then
        interval=$(cat "$CRASH_CTL" 2>/dev/null || echo 0)
        if [ -n "$interval" ] && [ "$interval" -gt 0 ] 2>/dev/null && [ "$elapsed" -ge "$interval" ]; then
            echo "fake-worker: simulated crash after ${elapsed}s"
            exit 1
        fi
    fi
done
