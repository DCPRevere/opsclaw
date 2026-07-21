#!/usr/bin/env bash
# proc-flapping — REQUIREMENT (brief §9: "the agent currently misses ...
# process restart-flapping cadence"). fake-worker crashes every N seconds
# (via its own crash-every control, target.Dockerfile/fake-worker.sh) and
# supervisord's autorestart brings it back — real restart churn, not a
# scripted illusion. This is the hard case: each individual restart looks
# fine (process comes back up quickly); the fault is only visible in the
# CADENCE across several restarts.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" sh -c "echo 5 > /run/opsclaw-sim/worker-crash-every"

# Verify real restart churn: sample the worker's start time / pid twice,
# 12s apart, spanning at least two crash cycles at a 5s cadence.
pid1="$(docker exec "$SIM_CONTAINER" pgrep -f fake-worker.sh | head -1)"
sleep 12
pid2="$(docker exec "$SIM_CONTAINER" pgrep -f fake-worker.sh | head -1)"

echo "proc-flapping: armed, worker pid ${pid1} -> ${pid2} over 12s (crash-every=5s)"

if [ "$pid1" = "$pid2" ]; then
    echo "proc-flapping: FAIL — worker pid did not change, no restart churn observed" >&2
    exit 1
fi
