#!/usr/bin/env bash
#
# OpsClaw Simulation Environment
#
# Usage:
#   ./sim.sh up                Start the simulation environment
#   ./sim.sh down              Stop and clean up
#   ./sim.sh arm <fault>       Inject a real fault (memory, …) inside the container
#   ./sim.sh disarm <fault>    Stop the fault, return to healthy
#   ./sim.sh status            Show current state and recent alerts
#   ./sim.sh logs              Tail OpsClaw daemon output
#   ./sim.sh webhooks          Show captured webhook notifications
#   ./sim.sh test [fault]      Run one or all scenarios with assertions
#
# Architecture: the sim-target is a real Ubuntu container with cgroup
# limits (8 GB RAM, 4 vCPU). Faults are induced by tools that actually
# consume resources (stress-ng, dd, tc), so the agent's reads of
# /proc/meminfo, top, vmstat etc. all see kernel-mediated truth — there
# is nothing to "see through." Per-scenario `expected.json` declares
# the alert the harness must observe within `max_detection_seconds`.
set -euo pipefail

SIMDIR="$(cd "$(dirname "$0")" && pwd)"
STATEDIR="$SIMDIR/.state"
OPSCLAW_BIN="$SIMDIR/../../target/debug/opsclaw"
SSH_KEY="$STATEDIR/sim_key"
SSH_PORT=2222
WEBHOOK_PORT=9999
CONTAINER_NAME="opsclaw-sim-target"

# Load dev/sim/.env if present (gitignored). We parse lines ourselves
# rather than `source`-ing the file so that values containing shell
# metacharacters (spaces, $, `, ;, &) are treated as literal strings
# instead of being executed. Use it to keep secrets like OPENAI_API_KEY
# out of your shell history.
if [ -f "$SIMDIR/.env" ]; then
    while IFS= read -r __sim_env_line || [ -n "$__sim_env_line" ]; do
        case "$__sim_env_line" in
            ''|'#'*) continue ;;
        esac
        if [[ "$__sim_env_line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            __sim_env_key="${BASH_REMATCH[1]}"
            __sim_env_val="${BASH_REMATCH[2]}"
            if [[ "$__sim_env_val" =~ ^\"(.*)\"$ ]] || [[ "$__sim_env_val" =~ ^\'(.*)\'$ ]]; then
                __sim_env_val="${BASH_REMATCH[1]}"
            fi
            export "$__sim_env_key=$__sim_env_val"
        else
            printf '[sim] warning: ignoring malformed line in .env: %s\n' "$__sim_env_line" >&2
        fi
    done < "$SIMDIR/.env"
    unset __sim_env_line __sim_env_key __sim_env_val
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${CYAN}[sim]${NC} $*"; }
ok()   { echo -e "${GREEN}[sim]${NC} $*"; }
warn() { echo -e "${YELLOW}[sim]${NC} $*"; }
err()  { echo -e "${RED}[sim]${NC} $*" >&2; }

# ── Helpers ──────────────────────────────────────────────────────────

wait_for_ssh() {
    log "Waiting for SSH on 127.0.0.1:$SSH_PORT..."
    for _ in $(seq 1 30); do
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o ConnectTimeout=1 -o LogLevel=ERROR \
               -i "$SSH_KEY" -p "$SSH_PORT" opsclaw@127.0.0.1 "echo ready" &>/dev/null; then
            ok "SSH is ready"
            return 0
        fi
        sleep 1
    done
    err "SSH did not become ready in 30 seconds"
    return 1
}

generate_config() {
    local key_content
    key_content=$(cat "$SSH_KEY")
    mkdir -p "$STATEDIR/.opsclaw"

    if [ -z "${OPENAI_API_KEY:-}" ]; then
        err "OPENAI_API_KEY is not set. Put it in dev/sim/.env or export it."
        return 1
    fi

    # The API key is intentionally NOT written to config.toml. The daemon
    # picks it up from ZEROCLAW_API_KEY at process start (see
    # apply_env_overrides in zeroclaw-config), which keeps the secret out
    # of any on-disk artefact.
    #
    # schema_version = 2 tells the runtime this is already on the current
    # schema, so the V1→V2 migration doesn't run and can't synthesise a
    # phantom providers.models.default entry.
    #
    # The webhook *channel* (not the opsclaw-specific [notifications]
    # block) is what the heartbeat agent uses for outbound notifications.
    # send_url points at the sim's webhook-sink container so the
    # harness can assert against captured POSTs.
    cat > "$STATEDIR/.opsclaw/config.toml" <<TOML
schema_version = 2

[secrets]
encrypt = false

[heartbeat]
enabled = true
interval_minutes = 1
two_phase = false
task_timeout_secs = 180

[gateway]
port = 0
host = "127.0.0.1"

[providers]
fallback = "openai"

[providers.models.openai]
name = "openai"
model = "gpt-5.4"

[channels.webhook]
enabled = true
port = 0
send_url = "http://127.0.0.1:$WEBHOOK_PORT/alerts"
send_method = "POST"

# opsclaw_notify reads from here directly (separate from the zeroclaw
# channel system above, which is for inbound/session chat).
[notifications]
webhook_url = "http://127.0.0.1:$WEBHOOK_PORT/alerts"
min_severity = "warning"

[[targets]]
name = "sim-target"
type = "ssh"
host = "127.0.0.1"
port = $SSH_PORT
user = "opsclaw"
autonomy = "dry-run"
key_secret = '''
$key_content
'''
TOML

    # Also create an upstream zeroclaw config so load_or_init doesn't complain.
    mkdir -p "$STATEDIR/.zeroclaw"
    cat > "$STATEDIR/.zeroclaw/config.toml" <<'TOML'
schema_version = 2

[secrets]
encrypt = false
TOML

    ok "Config generated at $STATEDIR/.opsclaw/config.toml"
}

scenario_path() {
    local name="$1"
    local p="$SIMDIR/scenarios/${name}.sh"
    if [ ! -f "$p" ]; then
        err "Unknown scenario: $name"
        echo "Available scenarios:" >&2
        ls "$SIMDIR/scenarios/"*.sh 2>/dev/null | xargs -I{} basename {} .sh | sed 's/^/  /' >&2
        return 1
    fi
    echo "$p"
}

# Run a scenario script inside the sim-target container in arm or disarm
# mode. We stream the script in via `docker exec` rather than using
# `docker cp`, because gVisor's sandbox rejects cp's tar-copy path.
# The script lives on the host so edits take effect without a rebuild.
run_scenario() {
    local name="$1"
    local action="$2"   # arm | disarm
    local local_path
    local_path=$(scenario_path "$name") || return 1

    # `cat > file` writes the scenario, then we bash it. Separate exec
    # calls because piping across exec gets tangled with -i.
    docker exec -i "$CONTAINER_NAME" bash -c 'cat > /sim/scenario.sh' < "$local_path"
    docker exec "$CONTAINER_NAME" bash /sim/scenario.sh "$action"
}

# ── Commands ─────────────────────────────────────────────────────────

cmd_up() {
    log "Starting OpsClaw simulation environment..."
    mkdir -p "$STATEDIR"

    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
        ok "SSH keypair generated"
    fi
    export SIM_SSH_PUBKEY
    SIM_SSH_PUBKEY=$(cat "${SSH_KEY}.pub")

    log "Starting Docker services..."
    (cd "$SIMDIR" && docker compose up -d --build)

    # The sim-target container needs a /sim directory writable by the
    # `opsclaw` user (nothing is mounted there now that scenarios run via
    # docker exec). Create it once on startup.
    docker exec "$CONTAINER_NAME" mkdir -p /sim

    wait_for_ssh

    log "Building OpsClaw..."
    (cd "$SIMDIR/../.." && cargo build -p opsclaw 2>&1 | tail -3)
    ok "OpsClaw built"

    generate_config

    : > "$STATEDIR/requests.jsonl"

    log "Starting OpsClaw daemon..."
    HOME="$STATEDIR" OPSCLAW_CONFIG_DIR="$STATEDIR/.opsclaw" \
        ZEROCLAW_API_KEY="$OPENAI_API_KEY" \
        "$OPSCLAW_BIN" daemon --host 127.0.0.1 --port 0 \
        > "$STATEDIR/opsclaw.log" 2>&1 &
    echo $! > "$STATEDIR/opsclaw.pid"
    ok "OpsClaw daemon running (PID $(cat "$STATEDIR/opsclaw.pid"))"

    echo
    echo -e "${BOLD}Simulation environment is ready.${NC}"
    echo
    echo "  Arm a fault:    $0 arm memory"
    echo "  Disarm:         $0 disarm memory"
    echo "  Test one:       $0 test memory"
    echo "  Test all:       $0 test"
    echo "  View webhooks:  $0 webhooks"
    echo "  Tear down:      $0 down"
}

cmd_down() {
    log "Tearing down simulation environment..."

    if [ -f "$STATEDIR/opsclaw.pid" ]; then
        local pid
        pid=$(cat "$STATEDIR/opsclaw.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            ok "OpsClaw daemon stopped (PID $pid)"
        fi
        rm -f "$STATEDIR/opsclaw.pid"
    fi

    (cd "$SIMDIR" && docker compose down -v 2>/dev/null) || true

    rm -f "$STATEDIR/opsclaw.log" "$STATEDIR/requests.jsonl"
    rm -rf "$STATEDIR/.opsclaw" "$STATEDIR/.zeroclaw"

    ok "Simulation environment stopped"
}

cmd_arm() {
    local name="${1:-}"
    if [ -z "$name" ]; then
        err "usage: $0 arm <fault>"
        return 1
    fi
    run_scenario "$name" arm
    ok "Armed: $name"
}

cmd_disarm() {
    local name="${1:-}"
    if [ -z "$name" ]; then
        err "usage: $0 disarm <fault>"
        return 1
    fi
    run_scenario "$name" disarm
    ok "Disarmed: $name"
}

cmd_status() {
    echo -e "${BOLD}=== OpsClaw Simulation Status ===${NC}"
    echo
    if [ -f "$STATEDIR/opsclaw.pid" ] && kill -0 "$(cat "$STATEDIR/opsclaw.pid")" 2>/dev/null; then
        echo -e "OpsClaw daemon:  ${GREEN}running${NC} (PID $(cat "$STATEDIR/opsclaw.pid"))"
    else
        echo -e "OpsClaw daemon:  ${RED}not running${NC}"
    fi
    echo
    echo -e "${BOLD}Recent OpsClaw output:${NC}"
    if [ -f "$STATEDIR/opsclaw.log" ]; then
        tail -10 "$STATEDIR/opsclaw.log"
    else
        echo "  (no log file)"
    fi
    echo
    echo -e "${BOLD}Recent webhook notifications:${NC}"
    if [ -s "$STATEDIR/requests.jsonl" ]; then
        tail -3 "$STATEDIR/requests.jsonl" | python3 -m json.tool 2>/dev/null \
            || tail -3 "$STATEDIR/requests.jsonl"
    else
        echo "  (no notifications yet)"
    fi
}

cmd_logs() {
    if [ ! -f "$STATEDIR/opsclaw.log" ]; then
        err "No log file found. Is the simulation running?"
        return 1
    fi
    tail -f "$STATEDIR/opsclaw.log"
}

cmd_webhooks() {
    if [ ! -s "$STATEDIR/requests.jsonl" ]; then
        echo "No webhook notifications captured yet."
        return 0
    fi
    while IFS= read -r line; do
        echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
        echo "---"
    done < "$STATEDIR/requests.jsonl"
}

# ── Test harness ─────────────────────────────────────────────────────

# Run one scenario end-to-end:
#   1. arm the fault inside the container
#   2. wait up to expected.max_detection_seconds for a webhook
#   3. assert the captured payload matches expected.alert
#   4. disarm
# Returns 0 on PASS, 1 on FAIL.
run_one_test() {
    local name="$1"
    local expected="$SIMDIR/scenarios/${name}.expected.json"
    if [ ! -f "$expected" ]; then
        err "No ${name}.expected.json — cannot assert"
        return 1
    fi

    local max_seconds
    max_seconds=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('max_detection_seconds',120))" "$expected")

    log "Test: $name (within ${max_seconds}s)"

    # Truncate webhook capture so we only see notifications from this run.
    : > "$STATEDIR/requests.jsonl"

    run_scenario "$name" arm

    local detected=false
    for _ in $(seq 1 "$max_seconds"); do
        if [ -s "$STATEDIR/requests.jsonl" ]; then
            detected=true
            break
        fi
        sleep 1
    done

    local result=1
    if $detected; then
        local payload
        payload=$(tail -1 "$STATEDIR/requests.jsonl")
        # Assertion: the captured webhook payload must mention at least one of
        # the keywords listed in expected.alert.content_keywords_any. We look
        # in the channel-delivered `content` field, falling back to the whole
        # raw payload if the structure differs.
        local verdict rc
        verdict=$(printf '%s' "$payload" | python3 - "$expected" <<'EOF'
import json, sys
expected = json.load(open(sys.argv[1]))
keywords = [k.lower() for k in expected.get('alert', {}).get('content_keywords_any', [])]
raw = sys.stdin.read()
try:
    msg = json.loads(raw)
except Exception as e:
    print(f'parse-error: {e}')
    sys.exit(1)
payload = msg.get('payload', msg)
content = payload.get('content', '') or json.dumps(payload)
content_l = content.lower()
hits = [k for k in keywords if k in content_l]
if not keywords:
    print('no-keywords-declared')
elif hits:
    print(f'hit: {hits}')
else:
    print(f'miss: looked for {keywords} in: {content!r}')
    sys.exit(2)
EOF
)
        rc=$?
        if [ $rc -eq 0 ]; then
            ok "PASS: $name — $verdict"
            result=0
        else
            err "FAIL: $name — $verdict"
        fi
    else
        err "FAIL: $name — no notification within ${max_seconds}s"
        tail -10 "$STATEDIR/opsclaw.log" 2>/dev/null || true
    fi

    run_scenario "$name" disarm
    return $result
}

cmd_test() {
    local target="${1:-}"

    # If a specific scenario is named, just run it; assume sim is already up.
    if [ -n "$target" ]; then
        run_one_test "$target"
        return $?
    fi

    # No name → full battery, including bring-up and tear-down.
    cmd_up

    local passed=0 failed=0
    for expected in "$SIMDIR"/scenarios/*.expected.json; do
        local name
        name=$(basename "$expected" .expected.json)
        echo
        if run_one_test "$name"; then
            passed=$((passed + 1))
        else
            failed=$((failed + 1))
        fi
    done

    echo
    echo -e "${BOLD}=== Test Results ===${NC}"
    echo -e "  ${GREEN}Passed: $passed${NC}"
    echo -e "  ${RED}Failed: $failed${NC}"

    cmd_down
    [ "$failed" -eq 0 ]
}

# ── Main ─────────────────────────────────────────────────────────────

case "${1:-}" in
    up)        cmd_up ;;
    down)      cmd_down ;;
    arm)       shift; cmd_arm "$@" ;;
    disarm)    shift; cmd_disarm "$@" ;;
    status)    cmd_status ;;
    logs)      cmd_logs ;;
    webhooks)  cmd_webhooks ;;
    test)      shift; cmd_test "$@" ;;
    *)
        cat <<HELP
OpsClaw Simulation Environment

Usage: $0 <command>

Commands:
  up               Start containers + opsclaw daemon
  down             Stop everything, clean state
  arm <fault>      Inject a real fault inside the sim-target container
  disarm <fault>   Stop the fault
  test [fault]     Run one scenario (no bring-up) or all (with bring-up)
  status           Current state and recent alerts
  logs             Tail OpsClaw daemon output
  webhooks         Show all captured webhook notifications

Available scenarios:
HELP
        ls "$SIMDIR"/scenarios/*.expected.json 2>/dev/null \
            | xargs -I{} basename {} .expected.json \
            | sed 's/^/  /'
        ;;
esac
