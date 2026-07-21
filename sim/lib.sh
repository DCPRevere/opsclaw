#!/usr/bin/env bash
# sim/lib.sh — shared helpers for sim/run.sh and scenario arm/disarm
# scripts. Sourced, not executed; every function assumes `set -euo pipefail`
# is already active in the caller.

SIM_IMAGE="${SIM_IMAGE:-opsclaw-sim-target:local}"
SIM_RUNTIME="${SIM_RUNTIME:-runsc}"

# sim_container_name SLOT
# Names are slot-scoped so scenarios can run in parallel isolated slots
# (brief §9: "runnable individually or in parallel isolated slots").
sim_container_name() {
    local slot="${1:?slot required}"
    echo "opsclaw-sim-${slot}"
}

# sim_ssh SLOT -- CMD...
# Runs CMD inside the target container over docker exec, standing in for
# the daemon's ssh executor without requiring a live daemon (the daemon's
# sim-runner integration is a later wave — see sim/run.sh TODO).
sim_exec() {
    local slot="$1"; shift
    local name; name="$(sim_container_name "$slot")"
    docker exec "$name" "$@"
}

sim_log() {
    printf '[sim] %s\n' "$*" >&2
}

sim_die() {
    printf '[sim] ERROR: %s\n' "$*" >&2
    exit 1
}

# sim_require_runsc
# Fails fast with a clear message rather than silently falling back to runc
# — a scenario "passing" under runc would not be testing the gVisor-bind-
# mount df-lying behaviour mount-scepticism depends on (DESIGN.md §3).
sim_require_runsc() {
    if ! docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q "$SIM_RUNTIME"; then
        sim_die "docker runtime '${SIM_RUNTIME}' is not registered (docker info | grep runsc). Install gVisor or set SIM_RUNTIME=runc for a degraded, non-gVisor run."
    fi
}

# sim_wait_for_ssh SLOT [TIMEOUT_SECS]
sim_wait_for_ssh() {
    local slot="$1" timeout="${2:-30}" name
    name="$(sim_container_name "$slot")"
    local waited=0
    while ! docker exec "$name" pgrep -x sshd >/dev/null 2>&1; do
        waited=$((waited + 1))
        [ "$waited" -ge "$timeout" ] && sim_die "sshd did not come up in ${name} within ${timeout}s"
        sleep 1
    done
}

# sim_wait_for_target_ready SLOT [TIMEOUT_SECS]
# Waits for sshd plus the fake-worker/fake-web/log-emitter services (via
# supervisorctl status, not pgrep -f — fake-web execs into python3/socat,
# replacing its own argv, so its script name disappears from /proc/*/cmdline)
# and for log-emitter's app.log to exist. Scenarios that touch app.log or
# the fake services on arm (log-flood, logfile-growth, proc-flapping,
# service-stopped, cascade) need this rather than sim_wait_for_ssh alone:
# supervisord starts all four programs roughly together but not atomically.
sim_wait_for_target_ready() {
    local slot="$1" timeout="${2:-30}" name
    name="$(sim_container_name "$slot")"
    sim_wait_for_ssh "$slot" "$timeout"

    local waited=0
    while true; do
        local statuses
        statuses="$(docker exec "$name" supervisorctl status fake-worker fake-web log-emitter 2>/dev/null || true)"
        if docker exec "$name" test -f /var/log/opsclaw-sim/app.log 2>/dev/null \
            && [ "$(printf '%s\n' "$statuses" | grep -c RUNNING)" -eq 3 ]; then
            break
        fi
        waited=$((waited + 1))
        [ "$waited" -ge "$timeout" ] && sim_die "fake services did not come up in ${name} within ${timeout}s"
        sleep 1
    done
}
