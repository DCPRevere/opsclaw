#!/usr/bin/env bash
# sim/daemon-harness.sh — the brief §9 acceptance assertion, shared by
# sim/run.sh (ssh targets) and k3d/run.sh (kubernetes targets). Sourced, not
# executed; every function assumes `set -euo pipefail` is already active in
# the caller. Lives under sim/ rather than a third top-level dir because
# sim/expected.schema.json is already the cross-shared schema both harnesses
# validate scenarios against — this is the same "shared-by-convention, not
# by a formal package boundary" relationship.
#
# What this file does NOT try to do, and why (report honestly, don't fake
# it): the daemon's `opsclaw_notify` tool (src/tools/notify.rs) fingerprints
# an incident as SHA-256(target, fault_class, resource) and persists only the
# fingerprint — `fault_class` itself is never written to the `incidents`
# table (migrations/0001_init.sql has no such column; confirmed against
# src/db/sqlite/incidents.rs). tests/evals.rs's in-process eval tier can
# still check fault_class exactly because it runs the agent loop in the SAME
# process and captures the tool call's raw JSON args directly. This harness
# runs the REAL daemon as a subprocess against a REAL sandboxed target (the
# whole point, brief §9: "a real fault injected on a real target"), so the
# only honest window onto what it did is what it persisted: the incident
# COUNT (the anti-spam assertion, equally load-bearing per brief §6) and its
# `severity`. Deliberately does NOT substring-match `signals`/`hypothesis`
# against `expected.json`'s `expected_signals` array either — those are
# free-text/model-phrased on one side and category labels ("cpu_pct",
# "loadavg_1m") on the other, so a substring check would be exactly the
# flaky prose-matching docs/EVALS.md warns against ("the model has room to
# phrase things differently between runs; the harness must not be flaky on
# wording"), not real evidence. "Correctly named" (fault_class itself) is
# verified by the live-eval tier's structural capture instead, which reads
# the tool call's raw args in-process rather than reconstructing them from
# what got persisted — see harness_assert_detection's comments below for
# exactly which checks are hard vs. skipped and which env gate gets you the
# exact fault_class match.

# ---- binary + workspace plumbing -------------------------------------

# harness_build_daemon_binaries
# Builds opsclaw + opsclaw-cli once. Honors CARGO_TARGET_DIR from the
# environment (repo convention: /mnt/neutron/opsclaw-target-sim) so a sim run
# shares incremental build state with normal `cargo build` instead of
# recompiling the whole workspace into a throwaway dir every invocation.
harness_build_daemon_binaries() {
    local repo_root="$1"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/mnt/neutron/opsclaw-target-sim}"
    harness_log "building opsclaw + opsclaw-cli (CARGO_TARGET_DIR=${CARGO_TARGET_DIR})"
    ( cd "$repo_root" && cargo build --bin opsclaw --bin opsclaw-cli >&2 )
    HARNESS_OPSCLAW_BIN="${CARGO_TARGET_DIR}/debug/opsclaw"
    HARNESS_OPSCLAW_CLI_BIN="${CARGO_TARGET_DIR}/debug/opsclaw-cli"
    [ -x "$HARNESS_OPSCLAW_BIN" ] || harness_die "build did not produce ${HARNESS_OPSCLAW_BIN}"
    [ -x "$HARNESS_OPSCLAW_CLI_BIN" ] || harness_die "build did not produce ${HARNESS_OPSCLAW_CLI_BIN}"
}

harness_log() {
    printf '[daemon-harness] %s\n' "$*" >&2
}

# harness_die: for ONE-TIME setup preconditions only (missing tools, a build
# that never produced a binary) — the same class of failure sim_die/k3d_die
# already use before their per-scenario loops start. Exits the whole
# process, which is correct there because there is no scenario in flight yet
# to fail independently of.
harness_die() {
    printf '[daemon-harness] ERROR: %s\n' "$*" >&2
    exit 1
}

# harness_fail: for assertions evaluated DURING a scenario run. Prints and
# returns 1 rather than exiting — callers are always run.sh/lib.sh functions
# already wrapped in `if ! ...; then rc=1; fi` (mirroring how arm.sh/disarm.sh
# failures are handled), so one scenario's detection failure surfaces as
# that scenario's FAIL and the run continues to the next scenario, exactly
# like an arm.sh failure does today. Using `exit` here instead would abort
# the entire sequential run.sh loop on the first failing scenario — sim_die/
# harness_die's "one-time setup" semantics, wrongly applied to a per-
# scenario check.
harness_fail() {
    printf '[daemon-harness] ERROR: %s\n' "$*" >&2
    return 1
}

# ---- scrubbed environment (DESIGN.md §6: "run the daemon with a scrubbed,
# non-inherited environment so an ambient real credential can never flip the
# daemon live mid-test" — gianna's web-tests lesson) ----------------------

# harness_daemon_env OPSCLAW_HOME
# Populates the global HARNESS_ENV array with "KEY=VALUE" pairs that make up
# the ENTIRE environment the daemon/CLI subprocess sees (an array, not a
# word-split string, so a value containing a space can never be mis-split
# into extra argv words the way `env -i $(harness_daemon_env ...)` would).
# Deliberately an ALLOWLIST, not a denylist: `env -i` starts the child from
# nothing, so a credential this function doesn't know to name can't leak by
# omission — the opposite of a denylist, which leaks anything it forgot to
# strip.
#
# PATH is required (the daemon's SshExecutor/KubernetesExecutor shell out to
# `ssh`/`kubectl` by bare name — src/targets/ssh.rs, src/targets/
# kubernetes.rs). HOME is required by ssh's own config lookups. OPSCLAW_HOME
# points every config/secret/db path at the throwaway dir this run owns.
# RUST_LOG/OPSCLAW_SCAN_INTERVAL_MINUTES are harness knobs, not credentials.
#
# Everything else — OPENROUTER_API_KEY, TELEGRAM_BOT_TOKEN, HINDSIGHT_URL,
# any operator's real ambient env — is simply ABSENT, which is what forces
# llm::build_chain (src/llm/chain.rs) down the clearly-logged FakeLlm path in
# deterministic mode. The live-tier path (harness_run_daemon_live, gated
# separately) re-adds OPENROUTER_API_KEY/OPSCLAW_MODELS explicitly and ONLY
# from this harness's own gate check, never by inheritance.
harness_daemon_env() {
    local opsclaw_home="$1"
    HARNESS_ENV=(
        "PATH=${PATH}"
        "HOME=${HOME}"
        "OPSCLAW_HOME=${opsclaw_home}"
        "OPSCLAW_LISTEN=127.0.0.1:0"
        "OPSCLAW_SCAN_INTERVAL_MINUTES=1"
        "RUST_LOG=opsclaw=info,warn"
    )
    # The ssh/kubernetes target credential env vars (harness_ssh_target_toml
    # / harness_kubernetes_target_toml export these as this process's OWN
    # env so the generated config.toml's "env:VAR" reference resolves) must
    # be forwarded explicitly — env -i starts the child from nothing, so
    # without this line the daemon's SecretRef::Env resolution would fail
    # with "not set" even though this script can see the value.
    [ -n "${OPSCLAW_HARNESS_SSH_IDENTITY:-}" ] &&
        HARNESS_ENV+=("OPSCLAW_HARNESS_SSH_IDENTITY=${OPSCLAW_HARNESS_SSH_IDENTITY}")
    [ -n "${OPSCLAW_HARNESS_KUBECONFIG:-}" ] &&
        HARNESS_ENV+=("OPSCLAW_HARNESS_KUBECONFIG=${OPSCLAW_HARNESS_KUBECONFIG}")
    true
}

# harness_run_daemon OPSCLAW_HOME LOGFILE
# Spawns `opsclaw` (the real daemon binary, boot::daemon_state — the exact
# path main.rs uses) as a background subprocess under a scrubbed env
# (harness_daemon_env), redirected to LOGFILE, prints its PID, and also
# drops it at OPSCLAW_HOME/.daemon.pid — harness_assert_detection reads that
# file rather than threading the PID through every call, since one
# OPSCLAW_HOME 1:1s with one running daemon for the life of a scenario.
#
# tick_seconds is baked into the generated config.toml by the caller
# (harness_write_config), not passed as an env override — DaemonCfg has no
# env-overlay knob for it (Config::apply_env_overlay only covers
# OPENROUTER_API_KEY/OPSCLAW_MODELS/HINDSIGHT_URL/TELEGRAM_BOT_TOKEN/
# OPSCLAW_LISTEN today), so a fast tick cadence for the harness has to be a
# config.toml field, same as everything else generated there.
harness_run_daemon() {
    local opsclaw_home="$1" logfile="$2" pid
    : "${HARNESS_OPSCLAW_BIN:?call harness_build_daemon_binaries first}"
    harness_daemon_env "$opsclaw_home"
    env -i "${HARNESS_ENV[@]}" "$HARNESS_OPSCLAW_BIN" >"$logfile" 2>&1 &
    pid=$!
    echo "$pid" > "${opsclaw_home}/.daemon.pid"
    echo "$pid"
}

# harness_stop_daemon PID
# SIGTERM then a bounded wait, SIGKILL if it doesn't exit — mirrors
# sim/run.sh's "force-reaped on every exit path" discipline (DESIGN.md §6)
# applied to the daemon subprocess itself, not just the sandboxed target
# container. Never fatal: a daemon that already exited (e.g. it crashed) is
# not a teardown failure.
harness_stop_daemon() {
    local pid="$1" waited=0
    kill -TERM "$pid" 2>/dev/null || return 0
    while kill -0 "$pid" 2>/dev/null; do
        waited=$((waited + 1))
        [ "$waited" -ge 10 ] && { kill -KILL "$pid" 2>/dev/null || true; break; }
        sleep 1
    done
    wait "$pid" 2>/dev/null || true
}

# harness_wait_daemon_ready OPSCLAW_HOME PID TIMEOUT_SECS
# The daemon is "ready" once its sqlite DB exists AND the process is still
# alive (a crash-on-boot must fail the harness loudly, not time out
# silently). We don't probe the HTTP listener — OPSCLAW_LISTEN is bound to
# 127.0.0.1:0 (ephemeral port, never a fixed one a parallel run could
# collide on) specifically so this harness has no reason to discover which
# port it landed on; everything it needs (incidents, doctor-equivalent
# reachability) goes through the SQLite file and opsclaw-cli, not HTTP.
harness_wait_daemon_ready() {
    local opsclaw_home="$1" pid="$2" timeout="${3:-30}" waited=0
    local db_path="${opsclaw_home}/opsclaw.sqlite3"
    while [ ! -f "$db_path" ]; do
        kill -0 "$pid" 2>/dev/null || { harness_fail "daemon (pid ${pid}) exited before becoming ready — see its log"; return 1; }
        waited=$((waited + 1))
        if [ "$waited" -ge "$timeout" ]; then
            harness_fail "daemon did not create ${db_path} within ${timeout}s"
            return 1
        fi
        sleep 1
    done
    kill -0 "$pid" 2>/dev/null || { harness_fail "daemon (pid ${pid}) exited immediately after creating its db — see its log"; return 1; }
}

# ---- config.toml generation ---------------------------------------------

# harness_write_config OPSCLAW_HOME TICK_SECONDS PROJECT_NAME ENV_NAME TARGET_TOML
# Writes a minimal, fully-faked (no llm.api_key -> FakeLlm; see
# src/llm/chain.rs) config.toml declaring exactly one project/env/target —
# the scenario's sandboxed target, expressed as TARGET_TOML (the caller
# builds the `[[project.env.target]]` block: sim's ssh stanza or k3d's
# kubernetes stanza — the two harnesses differ only here). PROJECT_NAME/
# ENV_NAME must match the scenario's `expected.json.fq_target` prefix
# EXACTLY (sim scenarios expect "sim::default::...", k3d scenarios expect
# "k3d::default::..." — see sim/expected.schema.json's fq_target doc and the
# committed expected.json files) or doctor/incidents lookups by fq_target
# will silently miss. Everything else is deliberately absent: no
# memory.hindsight_url, no telegram.bot_token, no http.jwt_secret
# (fully_faked() lets DEV_JWT_SECRET stand, fine — nothing real talks to
# this daemon's HTTP port), so Config::validate() passes without any of the
# live-mode requirements.
harness_write_config() {
    local opsclaw_home="$1" tick_seconds="$2" project_name="$3" env_name="$4" target_toml="$5"
    mkdir -p "$opsclaw_home"
    # daemon.db_path is set EXPLICITLY here, matching what boot::daemon_state
    # would compute as its default (home.join("opsclaw.sqlite3")) if left
    # unset — deliberately not relying on that default: opsclaw-cli's own
    # db_path resolution (src/bin/cli/main.rs resolve_db_path) does NOT
    # fall back to the same default the daemon computes, only reading
    # `daemon.db_path` from config and treating an absent value as "no
    # database exists yet" — true for a machine that has never run the
    # daemon, false here (the daemon just ran ahead of this CLI read), so an
    # explicit value keeps `opsclaw-cli incidents`/`doctor` pointed at the
    # exact file the daemon just wrote to instead of silently reporting "no
    # database".
    cat > "${opsclaw_home}/config.toml" <<EOF
[daemon]
tick_seconds = ${tick_seconds}
db_path = "${opsclaw_home}/opsclaw.sqlite3"

[[project]]
name = "${project_name}"
autonomy = "observe"

[[project.env]]
name = "${env_name}"

${target_toml}
EOF
}

# harness_ssh_target_toml FQ_NAME HOST PORT
# The [[project.env.target]] stanza for an ssh-kind target pointed at a sim
# container: address is bare "127.0.0.1" (ssh_port carries the docker
# port-mapped value — see the config/wiring.rs change this port lands with),
# credential is env:-referenced (never store:-referenced — no reason to
# touch the encrypted secret store for a throwaway identity file path that
# is itself already scoped to a throwaway per-scenario temp dir; the caller
# is responsible for `export`ing OPSCLAW_HARNESS_SSH_IDENTITY to the actual
# identity file path BEFORE calling this — see below), ssh_user is
# hardcoded "root" (sim/target.Dockerfile only ever creates a root account
# and installs authorized_keys under /root/.ssh — there is no other user to
# log in as, so this isn't a knob the caller needs), and
# ssh_strict_host_key_checking is "accept-new", NEVER "no": the sim target
# generates a fresh host key on every container start
# (sim/fixtures/entrypoint.sh: `ssh-keygen -A`), so there is no stable key to
# pin in a known_hosts file ahead of time, but accept-new still records and
# then verifies the key doesn't change WITHIN this one run's connections —
# "no" would additionally accept a key that changes mid-run, which
# accept-new correctly still refuses.
#
# Takes no identity-file argument itself and does NOT export
# OPSCLAW_HARNESS_SSH_IDENTITY — this function is always invoked as
# `target_toml="$(harness_ssh_target_toml ...)"` (command substitution),
# which runs it in a SUBSHELL; an export there would be invisible to the
# parent shell the instant the subshell exits, so the caller exports the var
# itself before calling this AND before harness_daemon_env. See sim/run.sh
# and k3d/run.sh's call sites.
harness_ssh_target_toml() {
    local fq_name="$1" host="$2" port="$3"
    cat <<EOF
[[project.env.target]]
name = "${fq_name}"
kind = "ssh"
address = "${host}"
credential = "env:OPSCLAW_HARNESS_SSH_IDENTITY"
ssh_port = ${port}
ssh_user = "root"
ssh_strict_host_key_checking = "accept-new"
expected_state = "running"
EOF
}

# harness_kubernetes_target_toml FQ_NAME
# The [[project.env.target]] stanza for a kubernetes-kind target: credential
# is the kubeconfig file PATH by env: reference (matches
# targets::wiring::executor_for_target's Kubernetes arm, which does
# `PathBuf::from(r.resolve(store)?)` — a path string, not file content).
# Same subshell caveat as harness_ssh_target_toml: takes no kubeconfig-path
# argument and does NOT export OPSCLAW_HARNESS_KUBECONFIG — the caller must,
# before calling this.
harness_kubernetes_target_toml() {
    local fq_name="$1"
    cat <<EOF
[[project.env.target]]
name = "${fq_name}"
kind = "kubernetes"
credential = "env:OPSCLAW_HARNESS_KUBECONFIG"
expected_state = "running"
EOF
}

# ---- deterministic-mode assertions (always run, no LLM needed) ---------

# harness_cli OPSCLAW_HOME -- ARGS...
# Runs opsclaw-cli against OPSCLAW_HOME under the SAME scrubbed env
# discipline as the daemon (harness_daemon_env) — doctor/incidents reads
# must see exactly the config/db the daemon itself would, nothing ambient.
harness_cli() {
    local opsclaw_home="$1"; shift
    : "${HARNESS_OPSCLAW_CLI_BIN:?call harness_build_daemon_binaries first}"
    harness_daemon_env "$opsclaw_home"
    env -i "${HARNESS_ENV[@]}" "$HARNESS_OPSCLAW_CLI_BIN" "$@"
}

# harness_assert_doctor_reaches_target OPSCLAW_HOME FQ_TARGET
# Deterministic assertion #1 (no LLM needed): `doctor` builds the executor
# through the EXACT SAME construction path the daemon boots with
# (targets::wiring::executor_for_target — src/cli/doctor.rs's own doc
# comment), so a green doctor probe here is real evidence the daemon's own
# transport (ssh/kubectl) can reach the sandboxed target, independent of
# whatever the LLM would or wouldn't do with that reachability.
harness_assert_doctor_reaches_target() {
    local opsclaw_home="$1" fq_target="$2" json ok
    json="$(harness_cli "$opsclaw_home" doctor --json)"
    ok="$(printf '%s' "$json" | jq -r --arg t "$fq_target" \
        '.checks[] | select(.name == ("target: " + $t)) | .ok')"
    if [ "$ok" != "true" ]; then
        harness_fail "doctor: target ${fq_target} not reachable — ${json}"
        return 1
    fi
    harness_log "PASS deterministic: doctor probe reaches ${fq_target}"
}

# harness_assert_doctor_reports_unreachable OPSCLAW_HOME FQ_TARGET
# The cluster-death counterpart to harness_assert_doctor_reaches_target: for
# a fault class whose entire premise is "the target is gone" (DESIGN.md §6,
# "untestable if the agent lived inside it"), a green probe means the fault
# ISN'T armed — this asserts doctor agrees the target is unreachable, which
# is the correct positive check for this one scenario, not a weaker version
# of the other one.
harness_assert_doctor_reports_unreachable() {
    local opsclaw_home="$1" fq_target="$2" json ok
    json="$(harness_cli "$opsclaw_home" doctor --json)"
    ok="$(printf '%s' "$json" | jq -r --arg t "$fq_target" \
        '.checks[] | select(.name == ("target: " + $t)) | .ok')"
    if [ "$ok" = "true" ]; then
        harness_fail "doctor: target ${fq_target} unexpectedly reachable — is the fault (cluster-death) actually armed? ${json}"
        return 1
    fi
    harness_log "PASS deterministic: doctor confirms ${fq_target} is unreachable (fault armed)"
}

# harness_assert_no_incidents OPSCLAW_HOME
# The silent-baseline / mount-scepticism control, checked structurally: the
# incidents table (what opsclaw_notify writes to, src/tools/notify.rs) has
# zero rows. This is the anti-spam/false-positive assertion and does not
# depend on the LLM being real — a FakeLlm calls no tools at all (see
# src/llm/fakes.rs), so under deterministic mode this assertion is trivially
# true and is really testing "the harness's wiring didn't accidentally open
# an incident some other way" (a boot bug, a stray seeded job, etc.), not
# the agent's judgement — that distinction is exactly why must_notify=false
# scenarios still need the LIVE tier to mean anything as a detection claim;
# see harness_assert_detection's header comment.
harness_assert_no_incidents() {
    local opsclaw_home="$1" count
    count="$(harness_cli "$opsclaw_home" incidents list --include-closed --json | jq 'length')"
    if [ "$count" != "0" ]; then
        harness_fail "expected zero incidents, found ${count}"
        return 1
    fi
    harness_log "PASS: zero incidents open"
}

# harness_wait_for_scan_tick LOGFILE FQ_NAME_SUFFIX TIMEOUT_SECS
# Deterministic assertion #2: the daemon actually FIRED the seeded scan job
# against this target, not just that it booted. `job fired` (or "fired but
# produced nothing") is scheduler::jobs::run_due_jobs's own tracing::info!
# line (src/scheduler/jobs.rs), emitted only when a due job is claimed and
# composed — never at boot, so this can't false-positive on startup log
# noise the way grepping for "wired N executor" would. The job's `name`
# field is seeded as "<project>::<env>::<target>-scan"
# (scheduler::jobs::seed_default_scan_jobs), so FQ_NAME_SUFFIX (e.g.
# "sim::default::baseline-target-scan") pins the match to THIS scenario's
# target, not any other job that might exist. Bounded by TIMEOUT_SECS —
# config.toml's tick_seconds=5 and boot.rs's OPSCLAW_SCAN_INTERVAL_MINUTES=1
# override (see that module's doc comment) keep the wait to roughly a
# minute, not the 30-minute production default.
harness_wait_for_scan_tick() {
    local logfile="$1" fq_name_suffix="$2" timeout="${3:-90}" waited=0
    while true; do
        if grep -F "${fq_name_suffix}" "$logfile" 2>/dev/null | grep -q 'job fired'; then
            return 0
        fi
        waited=$((waited + 1))
        if [ "$waited" -ge "$timeout" ]; then
            harness_fail "no 'job fired' for ${fq_name_suffix} seen in daemon log within ${timeout}s (${logfile})"
            return 1
        fi
        sleep 1
    done
}

# harness_count_job_fires LOGFILE FQ_NAME_SUFFIX
# How many times the seeded scan job for this target fired, per the daemon's
# own "job fired"/"job fired but produced nothing" log lines. Used for the
# anti-spam assertion across MULTIPLE ticks (brief §6: "deduplicated across
# heartbeat ticks") — the job firing more than once is expected and fine
# (that's the heartbeat working), what must NOT happen is more than one
# incident row for the same fingerprint, which harness_assert_no_incidents'
# sibling (the notify-count check in the live tier) covers; this counter
# exists so a caller can confirm at least 2 ticks were observed before
# trusting a "still zero incidents" read as meaning something beyond "we
# didn't wait long enough".
harness_count_job_fires() {
    local logfile="$1" fq_name_suffix="$2"
    grep -F "${fq_name_suffix}" "$logfile" 2>/dev/null | grep -c 'job fired' || true
}

# ---- live tier (env-gated, mirrors tests/evals.rs / docs/EVALS.md) -----

# harness_live_gated
# Same two-var gate as tests/evals.rs (docs/EVALS.md: "OPSCLAW_LIVE_EVALS=1
# ... plus OPENROUTER_API_KEY"), reused here rather than inventing a second
# convention — an operator who already knows the evals gate shouldn't have
# to learn a different one for the sim/k3d harness's live tier.
harness_live_gated() {
    [ "${OPSCLAW_LIVE_EVALS:-}" = "1" ] && [ -n "${OPENROUTER_API_KEY:-}" ]
}

# harness_run_daemon_live OPSCLAW_HOME LOGFILE
# Same as harness_run_daemon, EXCEPT the env is the scrubbed base PLUS
# OPENROUTER_API_KEY/OPSCLAW_MODELS forwarded explicitly from THIS harness's
# own already-checked gate (harness_live_gated) — never by ambient
# inheritance (an unrelated env var the operator's shell happens to have set
# must not silently flip a deterministic-mode run live; only a caller that
# has already gated on OPSCLAW_LIVE_EVALS=1 reaches this function at all).
#
# Config::apply_env_overlay (src/config/mod.rs) fills llm.api_key from
# OPENROUTER_API_KEY automatically when config.toml didn't set one — the
# generated config.toml never declares an `[llm]` block, so this is the ONLY
# place llm.api_key comes from in a live run. llm.models needs the same
# treatment for OPSCLAW_MODELS (apply_env_overlay's env var for it — note
# NOT "OPENROUTER_MODELS", which is docs/EVALS.md's/tests/evals.rs's own
# var name for the same concept; the two tiers don't share a config var,
# only the gate). Config::validate() refuses to boot with api_key set and
# models empty, so this function defaults to docs/EVALS.md's own fallback
# model when OPENROUTER_MODELS isn't set, keeping this harness's live tier
# and the live-eval tier defaulting to the same model absent an override.
harness_run_daemon_live() {
    local opsclaw_home="$1" logfile="$2" pid
    : "${HARNESS_OPSCLAW_BIN:?call harness_build_daemon_binaries first}"
    harness_daemon_env "$opsclaw_home"
    HARNESS_ENV+=("OPENROUTER_API_KEY=${OPENROUTER_API_KEY}")
    HARNESS_ENV+=("OPSCLAW_MODELS=${OPENROUTER_MODELS:-deepseek/deepseek-v4-flash}")
    env -i "${HARNESS_ENV[@]}" "$HARNESS_OPSCLAW_BIN" >"$logfile" 2>&1 &
    pid=$!
    echo "$pid" > "${opsclaw_home}/.daemon.pid"
    echo "$pid"
}

# ---- top-level per-scenario orchestration ------------------------------

# harness_assert_detection OPSCLAW_HOME LOGFILE FQ_TARGET FQ_JOB_NAME MUST_NOTIFY SEVERITY [EXPECT_REACHABLE]
# The brief §9 assertion, tying every helper above together for ONE
# scenario. Called after arm.sh (fault is armed and independently verified
# real) and before disarm.sh — the same slot the TODO block occupied.
#
# EXPECT_REACHABLE defaults to "true". The one scenario class that sets it
# to "false" is k3d's cluster-death (DESIGN.md §6: "untestable if the agent
# lived inside it") — the fault IS the target being unreachable, so a green
# doctor probe there would mean the fault ISN'T armed, not that detection
# works; asserting doctor reports UNREACHABLE is the correct check for that
# one fault class, not a skip of assertion #1.
#
# Deterministic mode (always runs, no LLM/network required):
#   1. doctor's target probe reaches the sandboxed target through the same
#      executor construction path the daemon boots with (or, when
#      EXPECT_REACHABLE=false, confirms doctor agrees the target is
#      UNREACHABLE — cluster-death's whole point).
#   2. the seeded scan job actually fires at least once (the daemon is not
#      just sitting there — it ran a real tick against this target).
#   3. the daemon process is still alive after that tick (survived the
#      armed fault; a crash here would be a harness-severity bug per
#      DESIGN.md §6, indistinguishable in blast-radius terms from a missed
#      detection).
#   4. incidents: because the deterministic-mode LLM is the clearly-logged
#      FakeLlm (src/llm/fakes.rs — calls NO tools, ever), the only incident
#      count that is EVER correct in this mode is zero. So deterministic
#      mode can only assert the count for must_notify=false scenarios
#      (silent-baseline, mount-scepticism) — for must_notify=true scenarios
#      it explicitly SKIPS the "was it detected" claim and says so, rather
#      than either lying (claiming a pass FakeLlm couldn't have earned) or
#      silently omitting the check. This is the harness's own version of
#      DESIGN.md's "print explicitly which assertions were SKIPPED, never
#      silently pass".
#
# Live mode (OPSCLAW_LIVE_EVALS=1 + OPENROUTER_API_KEY, harness_live_gated):
#   Same 1-3, PLUS the actual brief §9 claim: must_notify=true expects
#   exactly one incident after two observed ticks (anti-spam: a SECOND tick
#   firing must not open a second incident, since opsclaw_notify's dedup is
#   keyed on fingerprint, not tick — src/tools/notify.rs), with severity
#   matching expected.json; must_notify=false expects zero incidents across
#   the same two ticks. "Correctly named" (fault_class) is NOT checked here
#   even in live mode — see this file's header comment for exactly why
#   (fault_class isn't a persisted column) and tests/evals.rs's
#   notify_discipline/injection_resistance cases for where that exact check
#   DOES happen (in-process capture of the tool call's raw args).
harness_assert_detection() {
    local opsclaw_home="$1" logfile="$2" fq_target="$3" fq_job_name="$4" \
        must_notify="$5" expected_severity="$6" expect_reachable="${7:-true}"

    if [ "$expect_reachable" = "true" ]; then
        harness_assert_doctor_reaches_target "$opsclaw_home" "$fq_target" || return 1
    else
        harness_assert_doctor_reports_unreachable "$opsclaw_home" "$fq_target" || return 1
    fi

    harness_wait_for_scan_tick "$logfile" "$fq_job_name" 90 || return 1
    harness_log "PASS deterministic: scan tick fired against ${fq_target}"

    if ! kill -0 "$(cat "${opsclaw_home}/.daemon.pid")" 2>/dev/null; then
        harness_fail "daemon exited after the scan tick — see ${logfile}"
        return 1
    fi
    harness_log "PASS deterministic: daemon survived the armed fault (still running post-tick)"

    if harness_live_gated; then
        harness_log "live tier ARMED (OPSCLAW_LIVE_EVALS=1, OPENROUTER_API_KEY set) — waiting for a second tick to check anti-spam"
        local before after waited=0
        before="$(harness_count_job_fires "$logfile" "$fq_job_name")"
        while [ "$(harness_count_job_fires "$logfile" "$fq_job_name")" -le "$before" ]; do
            waited=$((waited + 1))
            if [ "$waited" -ge 90 ]; then
                harness_fail "no second tick observed within 90s for anti-spam check"
                return 1
            fi
            sleep 1
        done
        after="$(harness_count_job_fires "$logfile" "$fq_job_name")"
        harness_log "observed ${after} tick(s) fired against ${fq_target}"

        # Incident.target (src/domain/mod.rs FqTarget) derives plain
        # Serialize — it serializes as the STRUCT's fields
        # ({"project":...,"env":...,"target":...,"resource":null}), NOT
        # through its Display impl (which is what produces the
        # "project::env::target" form fq_target is in). Rebuilding that
        # same "project::env::target" string from the object's own fields
        # inside the jq filter (rather than comparing against fq_target's
        # string form via `tostring | contains`, which would compare against
        # the WRONG serialization and never match) is what makes this
        # comparison correct.
        local count
        count="$(harness_cli "$opsclaw_home" incidents list --include-closed --json \
            | jq --arg t "$fq_target" \
                '[.[] | select((.target.project + "::" + .target.env + "::" + .target.target) == $t)] | length')"
        if [ "$must_notify" = "true" ]; then
            if [ "$count" != "1" ]; then
                harness_fail "live: expected exactly 1 incident for ${fq_target} after ${after} ticks, found ${count} (anti-spam or detection failure)"
                return 1
            fi
            local sev
            sev="$(harness_cli "$opsclaw_home" incidents list --include-closed --json \
                | jq -r --arg t "$fq_target" \
                    '[.[] | select((.target.project + "::" + .target.env + "::" + .target.target) == $t)][0].severity')"
            if [ "$sev" != "$expected_severity" ]; then
                harness_fail "live: expected severity ${expected_severity}, got ${sev}"
                return 1
            fi
            harness_log "PASS live: exactly one incident, severity ${sev}, no spam across ${after} ticks"
        else
            if [ "$count" != "0" ]; then
                harness_fail "live: expected 0 incidents (silent baseline) for ${fq_target}, found ${count} — false positive"
                return 1
            fi
            harness_log "PASS live: silence held across ${after} ticks"
        fi
    else
        harness_log "SKIPPED live-tier assertions (exact detection / anti-spam / silence-under-a-real-model): set OPSCLAW_LIVE_EVALS=1 and OPENROUTER_API_KEY to run them (see docs/EVALS.md; same gate as tests/evals.rs)."
        if [ "$must_notify" = "false" ]; then
            harness_assert_no_incidents "$opsclaw_home" || return 1
            harness_log "PASS deterministic: silence holds under FakeLlm too (a necessary but not sufficient check — FakeLlm calls no tools at all, so this cannot distinguish 'correctly judged healthy' from 'incapable of ever alerting'; the live tier is what actually exercises judgement)"
        else
            harness_log "SKIPPED deterministic detection claim for must_notify=true: the fakes-mode LLM (src/llm/fakes.rs FakeLlm) never calls opsclaw_notify by construction, so a zero-incident read here would be vacuous, not a pass — see docs/EVALS.md for the live tier that actually exercises this."
        fi
    fi
}
