#!/usr/bin/env bash
# k3d/run.sh — Tier 2 kubernetes fault-injection harness orchestrator
# (DESIGN.md §6 "Tier 2, kubernetes").
#
# Creates a throwaway k3d cluster, runs each scenario's arm → verify → point
# a REAL opsclaw daemon at the cluster's kubeconfig as its `kubernetes`
# target and assert detection (sim/daemon-harness.sh — shared with sim/run.sh;
# see that file's header for exactly what's checked deterministically vs.
# gated behind the live-eval tier) → disarm → verify-clean, and deletes the
# cluster on every exit path.
#
# The daemon runs with a SCRUBBED, NON-INHERITED environment
# (daemon-harness.sh's harness_daemon_env — DESIGN.md §6, gianna's
# web-tests lesson) against a throwaway OPSCLAW_HOME + generated config.toml
# declaring this cluster as a `kubernetes` target (credential = the k3d
# kubeconfig path k3d_kubeconfig already writes per-slot, never merged into
# ~/.kube/config — same rule this harness already applies to every other
# kubectl/helm call here). Without OPSCLAW_LIVE_EVALS=1 + OPENROUTER_API_KEY
# (same two-var gate as tests/evals.rs/docs/EVALS.md), the daemon boots with
# the clearly-logged FakeLlm (src/llm/fakes.rs), so full "was the fault
# detected" assertions are impossible and are explicitly printed as SKIPPED
# rather than silently passed; what deterministic mode still proves: the
# daemon boots on the generated config, doctor's probe reaches the cluster
# through the same executor construction path the daemon boots with
# (kubectl version against the throwaway kubeconfig), a scan tick actually
# fires against the target, the daemon survives the armed fault, and (for
# must_notify=false scenarios) silence holds even under a tool-less fake.
#
# Usage:
#   k3d/run.sh                     # every scenario, one cluster, sequentially
#   k3d/run.sh crashloop            # one scenario
#   k3d/run.sh crashloop cluster-death   # a subset
#   k3d/run.sh --keep               # leave the cluster up after a pass (debugging)
#
# OPSCLAW_LIVE_EVALS=1 OPENROUTER_API_KEY=sk-or-... k3d/run.sh   # full acceptance incl. live detection
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3d/lib.sh
source "${SCRIPT_DIR}/lib.sh"

KEEP=0
SLOT_SUFFIX="$$"
SCENARIOS=()

for arg in "$@"; do
    case "$arg" in
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

k3d_require_tools
for bin in jq cargo; do
    command -v "$bin" >/dev/null 2>&1 || k3d_die "required tool '${bin}' not found on PATH"
done

# Private temp dir for kubeconfigs — never merged into ~/.kube/config (see
# k3d_kubeconfig in lib.sh). Reaped alongside the cluster on every exit path.
K3D_RUN_TMPDIR="$(mktemp -d)"
export K3D_RUN_TMPDIR

# Build the daemon binaries ONCE, up front (not per-scenario): every
# scenario boots a fresh daemon against its own throwaway OPSCLAW_HOME, but
# they all run the SAME opsclaw/opsclaw-cli build, and all point at the ONE
# cluster this run.sh invocation owns.
harness_build_daemon_binaries "${SCRIPT_DIR}/.."

SLOT="run${SLOT_SUFFIX}"
CLUSTER_NAME="$(k3d_cluster_name "$SLOT")"

# Reap on EVERY exit path — normal, a `set -e` abort mid-scenario, or a
# signal. Exactly sim/run.sh's discipline: a leaked k3d cluster is a full k3s
# server + containerd + load balancer container left running on the host, and
# a Ctrl-C'd run is exactly how that happens if teardown isn't trap-driven.
_final_reap() {
    local rc=$?
    if [ "$KEEP" -ne 0 ]; then
        k3d_log "--keep set, leaving cluster ${CLUSTER_NAME} up (kubeconfig: $(k3d_kubeconfig "$SLOT"))"
        return "$rc"
    fi
    k3d_log "tearing down ${CLUSTER_NAME}"
    k3d_delete_cluster "$SLOT"
    # Belt-and-braces: reap any other opsclaw-k3d-* cluster a previous
    # interrupted run left behind, same as sim's prefix-filter reap.
    k3d_reap_all
    rm -rf "$K3D_RUN_TMPDIR" 2>/dev/null || true
    return "$rc"
}
trap _final_reap EXIT INT TERM

k3d_create_cluster "$SLOT"

# run_one_scenario NAME
run_one_scenario() {
    local scenario="$1"
    local sdir="${SCRIPT_DIR}/scenarios/${scenario}"
    local rc=0
    local opsclaw_home; opsclaw_home="$(mktemp -d)"
    local daemon_log="${opsclaw_home}/daemon.log"
    local daemon_pid=""

    # Per-scenario daemon teardown — mirrors sim/run.sh's per-scenario
    # _reap_this. One daemon per scenario (not one shared across the whole
    # run) even though all scenarios share ONE cluster: a shared daemon
    # would carry incidents opened by a PREVIOUS scenario into the next
    # one's assertions, which would make "exactly one incident" and "zero
    # incidents" both meaningless — an incident count is only evidence about
    # THIS scenario's fault if nothing else could have put a row there.
    _reap_this_daemon() {
        [ -n "$daemon_pid" ] && harness_stop_daemon "$daemon_pid"
        if [ "${KEEP:-0}" -eq 0 ]; then
            rm -rf "$opsclaw_home" 2>/dev/null || true
        else
            k3d_log "[${scenario}] --keep set, leaving daemon home at ${opsclaw_home} (log: ${daemon_log})"
        fi
    }
    trap _reap_this_daemon RETURN

    [ -d "$sdir" ] || k3d_die "no such scenario: ${scenario} (looked in ${sdir})"
    [ -x "${sdir}/arm.sh" ] || k3d_die "${scenario}: arm.sh missing or not executable"
    [ -x "${sdir}/disarm.sh" ] || k3d_die "${scenario}: disarm.sh missing or not executable"
    [ -f "${sdir}/expected.json" ] || k3d_die "${scenario}: expected.json missing"

    k3d_log "[${scenario}] arming"
    if ! K3D_SLOT="$SLOT" K3D_CLUSTER="$CLUSTER_NAME" K3D_RUN_TMPDIR="$K3D_RUN_TMPDIR" \
            KUBECONFIG="$(k3d_kubeconfig "$SLOT")" "${sdir}/arm.sh"; then
        k3d_log "[${scenario}] FAIL: arm.sh exited nonzero"
        rc=1
    fi

    if [ "$rc" -eq 0 ]; then
        k3d_log "[${scenario}] fault armed — booting a real opsclaw daemon against it (DESIGN.md §6)"

        local fq_target project_name env_name target_toml must_notify severity
        fq_target="$(jq -r '.fq_target' "${sdir}/expected.json")"
        project_name="$(printf '%s' "$fq_target" | cut -d: -f1)"
        env_name="$(printf '%s' "$fq_target" | cut -d: -f3)"

        # Exported BEFORE calling harness_kubernetes_target_toml: that
        # function runs in a command-substitution subshell, so an export
        # made INSIDE it never reaches this shell — see its doc comment.
        # Declared and assigned separately (not `export FOO="$(...)"`) so a
        # failing k3d_kubeconfig subshell's exit code isn't masked by
        # export's own (SC2155).
        local kubeconfig_path
        kubeconfig_path="$(k3d_kubeconfig "$SLOT")"
        export OPSCLAW_HARNESS_KUBECONFIG="$kubeconfig_path"
        target_toml="$(harness_kubernetes_target_toml "${fq_target##*::}")"
        harness_write_config "$opsclaw_home" 5 "$project_name" "$env_name" "$target_toml"

        if harness_live_gated; then
            daemon_pid="$(harness_run_daemon_live "$opsclaw_home" "$daemon_log")"
        else
            daemon_pid="$(harness_run_daemon "$opsclaw_home" "$daemon_log")"
        fi

        if ! harness_wait_daemon_ready "$opsclaw_home" "$daemon_pid" 30; then
            k3d_log "[${scenario}] FAIL: daemon did not become ready — see ${daemon_log}"
            rc=1
        else
            k3d_log "[${scenario}] daemon up (pid ${daemon_pid}, home ${opsclaw_home}, log ${daemon_log})"

            must_notify="$(jq -r '.must_notify' "${sdir}/expected.json")"
            severity="$(jq -r '.severity' "${sdir}/expected.json")"

            # cluster-death's fault IS "the target is unreachable" (DESIGN.md
            # §6: "untestable if the agent lived inside it") — a green doctor
            # probe there would mean the fault isn't armed, not that
            # detection works, so this is the one scenario that expects
            # doctor to report UNREACHABLE rather than reachable.
            local expect_reachable="true"
            [ "$scenario" = "cluster-death" ] && expect_reachable="false"

            if ! harness_assert_detection "$opsclaw_home" "$daemon_log" "$fq_target" \
                    "${fq_target}-scan" "$must_notify" "$severity" "$expect_reachable"; then
                k3d_log "[${scenario}] FAIL: daemon-detection assertion failed"
                rc=1
            fi
        fi
    fi

    k3d_log "[${scenario}] disarming"
    if ! K3D_SLOT="$SLOT" K3D_CLUSTER="$CLUSTER_NAME" K3D_RUN_TMPDIR="$K3D_RUN_TMPDIR" \
            KUBECONFIG="$(k3d_kubeconfig "$SLOT")" "${sdir}/disarm.sh"; then
        k3d_log "[${scenario}] WARN: disarm.sh exited nonzero"
        rc=1
    fi

    if [ "$rc" -eq 0 ]; then
        k3d_log "[${scenario}] PASS"
    else
        k3d_log "[${scenario}] FAIL"
    fi
    return "$rc"
}

overall_rc=0
for scenario in "${SCENARIOS[@]}"; do
    run_one_scenario "$scenario" || overall_rc=1
done

if [ "$overall_rc" -eq 0 ]; then
    if harness_live_gated; then
        k3d_log "all scenarios passed — including live-tier detection (OPSCLAW_LIVE_EVALS=1)"
    else
        k3d_log "all scenarios passed (deterministic tier only — see 'SKIPPED live-tier' lines above; set OPSCLAW_LIVE_EVALS=1 + OPENROUTER_API_KEY for full DESIGN.md §6 detection assertions)"
    fi
else
    k3d_log "one or more scenarios FAILED"
fi
exit "$overall_rc"
