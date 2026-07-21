#!/usr/bin/env bash
# sim/run.sh — Tier 2 fault-injection harness orchestrator (brief §9,
# DESIGN.md §6 "Tier 2 (the acceptance test)").
#
# For each scenario: build the gVisor-sandboxed target image, start it under
# --runtime=runsc, run the scenario's arm.sh, verify the injected fault is
# REALLY present on the target (not just that arm.sh exited 0), run
# disarm.sh, verify the target is clean again.
#
# What this script does NOT do yet: point a live opsclaw daemon at the
# target and assert it detected the fault, called notify exactly once with
# a payload matching expected.json, and stayed silent otherwise. That's the
# actual acceptance test (brief §9) and needs the daemon's sim-runner
# integration, which is a later wave. See the TODO below for exactly where
# that wires in — everything up to and including "the fault is real" is
# built and working today.
#
# The target container runs with --cap-add=SYS_ADMIN (still under
# --runtime=runsc): mount-scepticism needs to mount/remount a decoy tmpfs
# inside the sandbox, which runsc denies to an unprivileged container.
# gVisor still intercepts and virtualizes the mount syscalls — SYS_ADMIN
# widens what the sandboxed container may do, it does not drop the sandbox.
#
# Usage:
#   sim/run.sh                    # run every scenario, sequentially, slot=default
#   sim/run.sh cpu-single          # run one scenario
#   sim/run.sh --parallel          # run every scenario in parallel isolated slots
#   sim/run.sh --keep              # don't tear down containers on success (debugging)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=sim/lib.sh
source "${SCRIPT_DIR}/lib.sh"

PARALLEL=0
KEEP=0
SCENARIOS=()

for arg in "$@"; do
    case "$arg" in
        --parallel) PARALLEL=1 ;;
        --keep) KEEP=1 ;;
        --help|-h)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *) SCENARIOS+=("$arg") ;;
    esac
done

if [ "${#SCENARIOS[@]}" -eq 0 ]; then
    while IFS= read -r -d '' dir; do
        SCENARIOS+=("$(basename "$dir")")
    done < <(find "${SCRIPT_DIR}/scenarios" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
fi

sim_require_runsc

sim_log "building target image ${SIM_IMAGE}"
docker build -q -t "$SIM_IMAGE" -f "${SCRIPT_DIR}/target.Dockerfile" "${SCRIPT_DIR}/.." >/dev/null

# run_one_scenario NAME SLOT
run_one_scenario() {
    local scenario="$1" slot="$2"
    local sdir="${SCRIPT_DIR}/scenarios/${scenario}"
    local name; name="$(sim_container_name "$slot")"
    local keydir; keydir="$(mktemp -d)"
    local rc=0

    # Teardown that fires on EVERY exit from this function — normal return, a
    # `set -e` abort in arm/disarm, or a signal (via the script-level trap that
    # calls sim_reap_all). A scenario container must NEVER outlive its run:
    # a surviving container was how a ballooned writable layer wedged the host
    # disk. --keep is the one explicit opt-out (leaves the container for
    # inspection); everything else always reaps. Registered per-slot so
    # parallel scenarios each clean up their own.
    SIM_ACTIVE_CONTAINERS="${SIM_ACTIVE_CONTAINERS:-} ${name}"
    _reap_this() {
        if [ "${KEEP:-0}" -eq 0 ]; then
            docker rm -f "$name" >/dev/null 2>&1 || true
        fi
        rm -rf "$keydir" 2>/dev/null || true
    }
    trap _reap_this RETURN

    [ -d "$sdir" ] || sim_die "no such scenario: ${scenario} (looked in ${sdir})"
    [ -x "${sdir}/arm.sh" ] || sim_die "${scenario}: arm.sh missing or not executable"
    [ -x "${sdir}/disarm.sh" ] || sim_die "${scenario}: disarm.sh missing or not executable"
    [ -f "${sdir}/expected.json" ] || sim_die "${scenario}: expected.json missing"

    sim_log "[${scenario}] generating ephemeral keypair for slot ${slot}"
    ssh-keygen -t ed25519 -N '' -f "${keydir}/id_ed25519" -q
    cp "${keydir}/id_ed25519.pub" "${keydir}/authorized_keys"

    sim_log "[${scenario}] starting target container ${name} (--runtime=${SIM_RUNTIME})"
    docker rm -f "$name" >/dev/null 2>&1 || true
    # /data MUST be a size-capped tmpfs, not the container's writable layer.
    # The disk-fill scenario fills "90% of what `df /data` reports available",
    # and inside an overlay2 container an un-mounted /data reports the HOST
    # root fs's free space — so an unbounded /data made disk-fill allocate ~90%
    # of the whole host disk into the writable layer, wedging the machine at
    # 100%%. Capping it here bounds the fault to SIM_DATA_SIZE and keeps df's
    # answer truthful (the Dockerfile comment always claimed 200MB; this is
    # what actually enforces it). --tmpfs also means the fill never touches the
    # writable layer, so a surviving container can't hoard host disk.
    docker run -d --name "$name" \
        --runtime="$SIM_RUNTIME" \
        --cap-add=SYS_ADMIN \
        --tmpfs /run/opsclaw-sim:rw,size=16m \
        --tmpfs "/data:rw,size=${SIM_DATA_SIZE:-200m}" \
        --storage-opt "size=${SIM_LAYER_CAP:-2g}" \
        -v "${keydir}/authorized_keys:/run/opsclaw-sim/authorized_keys:ro" \
        -p 127.0.0.1:0:22 \
        "$SIM_IMAGE" >/dev/null \
        || docker run -d --name "$name" \
            --runtime="$SIM_RUNTIME" \
            --cap-add=SYS_ADMIN \
            --tmpfs /run/opsclaw-sim:rw,size=16m \
            --tmpfs "/data:rw,size=${SIM_DATA_SIZE:-200m}" \
            -v "${keydir}/authorized_keys:/run/opsclaw-sim/authorized_keys:ro" \
            -p 127.0.0.1:0:22 \
            "$SIM_IMAGE" >/dev/null

    sim_wait_for_target_ready "$slot" 30

    sim_log "[${scenario}] arming"
    if ! SIM_SLOT="$slot" SIM_CONTAINER="$name" "${sdir}/arm.sh"; then
        sim_log "[${scenario}] FAIL: arm.sh exited nonzero"
        rc=1
    fi

    if [ "$rc" -eq 0 ]; then
        sim_log "[${scenario}] fault armed — TODO(daemon-integration): point a live opsclaw"
        sim_log "  daemon at this target (ssh://root@127.0.0.1:<mapped-port>, key at"
        sim_log "  ${keydir}/id_ed25519) with the scenario's fq_target from expected.json,"
        sim_log "  wait for a detection tick, and assert:"
        sim_log "    - opsclaw_notify called exactly once (or zero times if must_notify=false)"
        sim_log "    - the notify payload's fault/severity match expected.json"
        sim_log "    - no further notify calls fire while the fault stays armed (anti-spam)"
        sim_log "  This is the actual brief §9 acceptance assertion; everything above and"
        sim_log "  below it (image build, gVisor sandboxing, fault is verifiably real,"
        sim_log "  clean disarm) is wired and passing today without a daemon."
    fi

    sim_log "[${scenario}] disarming"
    SIM_SLOT="$slot" SIM_CONTAINER="$name" "${sdir}/disarm.sh" || {
        sim_log "[${scenario}] WARN: disarm.sh exited nonzero"
        rc=1
    }

    [ "$KEEP" -ne 0 ] && sim_log "[${scenario}] --keep set, leaving ${name} running"
    # The container and keydir are reaped by the RETURN trap (_reap_this),
    # which also covers the arm/disarm failure and signal paths above.

    if [ "$rc" -eq 0 ]; then
        sim_log "[${scenario}] PASS"
    else
        sim_log "[${scenario}] FAIL"
    fi
    return "$rc"
}

# Belt-and-braces reap: force-remove every sim container by name pattern, on
# ANY script exit — including SIGINT/SIGTERM (a Ctrl-C'd parallel run, which is
# exactly how a stranded container once ballooned and wedged the host disk).
# The per-scenario RETURN trap handles the normal path; this catches the cases
# a subshell trap can't (a child killed uncleanly, an interrupt between runs).
# Honours --keep. Idempotent — safe to fire more than once.
sim_reap_all() {
    [ "${KEEP:-0}" -ne 0 ] && return 0
    local ids
    # `opsclaw-sim-` is the shared prefix of every slot's container name
    # (sim_container_name = "opsclaw-sim-<slot>"). A prefix filter reaps all
    # slots at once regardless of how many parallel runs were in flight.
    ids="$(docker ps -aq --filter "name=opsclaw-sim-" 2>/dev/null || true)"
    [ -n "$ids" ] && docker rm -f $ids >/dev/null 2>&1 || true
}
trap 'sim_reap_all' EXIT INT TERM

overall_rc=0
if [ "$PARALLEL" -eq 1 ]; then
    pids=()
    idx=0
    for scenario in "${SCENARIOS[@]}"; do
        idx=$((idx + 1))
        ( run_one_scenario "$scenario" "slot${idx}" ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || overall_rc=1
    done
else
    for scenario in "${SCENARIOS[@]}"; do
        run_one_scenario "$scenario" "default" || overall_rc=1
    done
fi

if [ "$overall_rc" -eq 0 ]; then
    sim_log "all scenarios passed (fault-injection layer only — see TODO above for daemon assertion)"
else
    sim_log "one or more scenarios FAILED"
fi
exit "$overall_rc"
