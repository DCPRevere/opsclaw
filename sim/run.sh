#!/usr/bin/env bash
# sim/run.sh — Tier 2 fault-injection harness orchestrator (brief §9,
# DESIGN.md §6 "Tier 2 (the acceptance test)").
#
# For each scenario: build the gVisor-sandboxed target image, start it under
# --runtime=runsc, run the scenario's arm.sh, verify the injected fault is
# REALLY present on the target (not just that arm.sh exited 0), point a
# REAL opsclaw daemon at it and assert detection (sim/daemon-harness.sh —
# see its header comment for exactly what's checked deterministically vs.
# gated behind the live-eval tier), run disarm.sh, verify the target is
# clean again.
#
# The daemon runs with a SCRUBBED, NON-INHERITED environment
# (daemon-harness.sh's harness_daemon_env — DESIGN.md §6, gianna's
# web-tests lesson: an ambient real credential must never flip the daemon
# live mid-test) against a throwaway OPSCLAW_HOME + generated config.toml
# declaring the sim container as an `ssh` target. Without OPSCLAW_LIVE_EVALS=1
# + OPENROUTER_API_KEY (same two-var gate as tests/evals.rs/docs/EVALS.md),
# the daemon boots with the clearly-logged FakeLlm (src/llm/fakes.rs — no
# network calls, no tool calls ever), so full "was the fault detected"
# assertions are impossible and are explicitly printed as SKIPPED rather
# than silently passed; what deterministic mode still proves for real: the
# daemon boots on the generated config, doctor's probe reaches the target
# through the same executor construction path the daemon boots with, a scan
# tick actually fires against the target, the daemon survives the armed
# fault, and (for must_notify=false scenarios) silence holds even under a
# tool-less fake — see daemon-harness.sh's harness_assert_detection doc.
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
#
# OPSCLAW_LIVE_EVALS=1 OPENROUTER_API_KEY=sk-or-... sim/run.sh   # full acceptance incl. live detection
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
for bin in jq cargo ssh; do
    command -v "$bin" >/dev/null 2>&1 || sim_die "required tool '${bin}' not found on PATH"
done

sim_log "building target image ${SIM_IMAGE}"
docker build -q -t "$SIM_IMAGE" -f "${SCRIPT_DIR}/target.Dockerfile" "${SCRIPT_DIR}/.." >/dev/null

# Build the daemon binaries ONCE, up front (not per-scenario): every scenario
# points a freshly-booted daemon at its own throwaway OPSCLAW_HOME, but they
# all run the SAME opsclaw/opsclaw-cli build.
harness_build_daemon_binaries "${SCRIPT_DIR}/.."

# run_one_scenario NAME SLOT
run_one_scenario() {
    local scenario="$1" slot="$2"
    local sdir="${SCRIPT_DIR}/scenarios/${scenario}"
    local name; name="$(sim_container_name "$slot")"
    local keydir; keydir="$(mktemp -d)"
    local opsclaw_home; opsclaw_home="$(mktemp -d)"
    local daemon_log="${opsclaw_home}/daemon.log"
    local daemon_pid=""
    local rc=0

    # Teardown that fires on EVERY exit from this function — normal return, a
    # `set -e` abort in arm/disarm, or a signal (via the script-level trap that
    # calls sim_reap_all). A scenario container must NEVER outlive its run:
    # a surviving container was how a ballooned writable layer wedged the host
    # disk. --keep is the one explicit opt-out (leaves the container for
    # inspection); everything else always reaps. Registered per-slot so
    # parallel scenarios each clean up their own. The daemon subprocess gets
    # the exact same discipline (harness_stop_daemon: SIGTERM then bounded
    # SIGKILL) — a leaked daemon process holding an open ssh connection to a
    # container this trap is about to `docker rm -f` is just as much a stray
    # process as a leaked container, even though it runs on the host, not in
    # docker.
    SIM_ACTIVE_CONTAINERS="${SIM_ACTIVE_CONTAINERS:-} ${name}"
    _reap_this() {
        [ -n "$daemon_pid" ] && harness_stop_daemon "$daemon_pid"
        if [ "${KEEP:-0}" -eq 0 ]; then
            docker rm -f "$name" >/dev/null 2>&1 || true
            rm -rf "$opsclaw_home" 2>/dev/null || true
        else
            sim_log "[${scenario}] --keep set, leaving daemon home at ${opsclaw_home} (log: ${daemon_log})"
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
    # --memory/--cpus apply the same rule to RAM and CPU: stress-ng scenarios
    # size themselves off /proc/meminfo ("--vm-bytes 85%"), and gVisor reports
    # the cgroup limit as total — without the cap, "85%" means 85% of the
    # HOST's RAM (~50GB on the dev machine, observed before this cap landed).
    # --storage-opt (writable-layer cap, extra belt) needs overlay-on-xfs with
    # pquota and fails outright elsewhere — hence the silenced first attempt
    # and the no-storage-opt fallback; a real startup error still surfaces
    # from the fallback run.
    docker run -d --name "$name" \
        --runtime="$SIM_RUNTIME" \
        --cap-add=SYS_ADMIN \
        --memory "${SIM_MEM_LIMIT:-1g}" --memory-swap "${SIM_MEM_LIMIT:-1g}" \
        --cpus "${SIM_CPU_LIMIT:-4}" \
        --tmpfs /run/opsclaw-sim:rw,size=16m \
        --tmpfs "/data:rw,size=${SIM_DATA_SIZE:-200m}" \
        --storage-opt "size=${SIM_LAYER_CAP:-2g}" \
        -v "${keydir}/authorized_keys:/run/opsclaw-sim/authorized_keys:ro" \
        -p 127.0.0.1:0:22 \
        "$SIM_IMAGE" >/dev/null 2>&1 \
        || docker run -d --name "$name" \
            --runtime="$SIM_RUNTIME" \
            --cap-add=SYS_ADMIN \
            --memory "${SIM_MEM_LIMIT:-1g}" --memory-swap "${SIM_MEM_LIMIT:-1g}" \
            --cpus "${SIM_CPU_LIMIT:-4}" \
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
        sim_log "[${scenario}] fault armed — booting a real opsclaw daemon against it (brief §9)"

        local fq_target ssh_host ssh_port project_name env_name target_name
        fq_target="$(jq -r '.fq_target' "${sdir}/expected.json")"
        project_name="$(printf '%s' "$fq_target" | cut -d: -f1)"
        env_name="$(printf '%s' "$fq_target" | cut -d: -f3)"
        target_name="${fq_target##*::}"
        ssh_host="127.0.0.1"
        ssh_port="$(docker port "$name" 22/tcp | tail -n1 | cut -d: -f2)"

        if [ -z "$ssh_port" ]; then
            sim_log "[${scenario}] FAIL: could not determine mapped ssh port for ${name}"
            rc=1
        else
            local target_toml
            # Exported (not just set) BEFORE calling harness_ssh_target_toml:
            # that function runs in a command-substitution subshell, so an
            # export made INSIDE it never reaches this shell — see its doc
            # comment. This is what harness_daemon_env forwards into the
            # scrubbed env -i invocation later (harness_run_daemon).
            export OPSCLAW_HARNESS_SSH_IDENTITY="${keydir}/id_ed25519"
            target_toml="$(harness_ssh_target_toml "$target_name" "$ssh_host" "$ssh_port")"
            harness_write_config "$opsclaw_home" 5 "$project_name" "$env_name" "$target_toml"

            if harness_live_gated; then
                daemon_pid="$(harness_run_daemon_live "$opsclaw_home" "$daemon_log")"
            else
                daemon_pid="$(harness_run_daemon "$opsclaw_home" "$daemon_log")"
            fi

            if ! harness_wait_daemon_ready "$opsclaw_home" "$daemon_pid" 30; then
                sim_log "[${scenario}] FAIL: daemon did not become ready — see ${daemon_log}"
                rc=1
            else
                sim_log "[${scenario}] daemon up (pid ${daemon_pid}, home ${opsclaw_home}, log ${daemon_log})"

                local must_notify severity
                must_notify="$(jq -r '.must_notify' "${sdir}/expected.json")"
                severity="$(jq -r '.severity' "${sdir}/expected.json")"

                if ! harness_assert_detection "$opsclaw_home" "$daemon_log" "$fq_target" \
                        "${fq_target}-scan" "$must_notify" "$severity"; then
                    sim_log "[${scenario}] FAIL: daemon-detection assertion failed"
                    rc=1
                fi
            fi
        fi
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
    if harness_live_gated; then
        sim_log "all scenarios passed — including live-tier detection (OPSCLAW_LIVE_EVALS=1)"
    else
        sim_log "all scenarios passed (deterministic tier only — see 'SKIPPED live-tier' lines above; set OPSCLAW_LIVE_EVALS=1 + OPENROUTER_API_KEY for full brief §9 detection assertions)"
    fi
else
    sim_log "one or more scenarios FAILED"
fi
exit "$overall_rc"
