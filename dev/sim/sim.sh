#!/usr/bin/env bash
#
# OpsClaw Simulation Environment
#
# Usage:
#   ./sim.sh up          Start the simulation environment
#   ./sim.sh down        Stop and clean up
#   ./sim.sh fault NAME  Inject a fault (memory, disk, load, container, restart, service, port, crisis)
#   ./sim.sh clear       Clear faults, return to healthy baseline
#   ./sim.sh status      Show current state and recent alerts
#   ./sim.sh logs        Tail OpsClaw output
#   ./sim.sh webhooks    Show captured webhook notifications
#   ./sim.sh test        Run all scenarios automatically (CI mode)
#
set -euo pipefail

SIMDIR="$(cd "$(dirname "$0")" && pwd)"
STATEDIR="$SIMDIR/.state"
OPSCLAW_BIN="$SIMDIR/../../target/debug/opsclaw"
SSH_KEY="$STATEDIR/sim_key"
SSH_PORT=2222
WEBHOOK_PORT=9999
CONTAINER_NAME="opsclaw-sim-target"

# Colors
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
    log "Waiting for SSH on port $SSH_PORT..."
    for i in $(seq 1 30); do
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

    cat > "$STATEDIR/.opsclaw/config.toml" <<TOML
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

[[projects]]
name = "sim-target"
type = "ssh"
host = "127.0.0.1"
port = $SSH_PORT
user = "opsclaw"
autonomy = "dry-run"
key_secret = '''
$key_content
'''

[notifications]
webhook_url = "http://127.0.0.1:$WEBHOOK_PORT/alerts"
min_severity = "warning"
TOML

    # Also create an upstream zeroclaw config so load_or_init doesn't complain
    mkdir -p "$STATEDIR/.zeroclaw"
    cat > "$STATEDIR/.zeroclaw/config.toml" <<TOML
[secrets]
encrypt = false
TOML

    ok "Config generated at $STATEDIR/.opsclaw/config.toml"
}

inject_scenario() {
    local scenario="$1"
    local scenario_file="$SIMDIR/scenarios/${scenario}.sh"

    if [ ! -f "$scenario_file" ]; then
        err "Unknown scenario: $scenario"
        echo "Available scenarios:"
        ls "$SIMDIR/scenarios/"*.sh | xargs -I{} basename {} .sh | sed 's/^/  /'
        return 1
    fi

    docker cp "$scenario_file" "$CONTAINER_NAME:/sim/active-scenario.sh"
    ok "Scenario '${scenario}' activated"
}

# ── Commands ─────────────────────────────────────────────────────────

cmd_up() {
    log "Starting OpsClaw simulation environment..."

    # Create state directory
    mkdir -p "$STATEDIR"

    # Generate SSH keypair
    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
        ok "SSH keypair generated"
    fi

    export SIM_SSH_PUBKEY
    SIM_SSH_PUBKEY=$(cat "${SSH_KEY}.pub")

    # Start Docker services
    log "Starting Docker services..."
    cd "$SIMDIR"
    docker compose up -d --build

    # Wait for SSH
    wait_for_ssh

    # Set baseline scenario
    inject_scenario baseline

    # Build OpsClaw
    log "Building OpsClaw..."
    (cd "$SIMDIR/../.." && cargo build -p opsclaw 2>&1 | tail -3)
    ok "OpsClaw built"

    # Generate config
    generate_config

    # Clear old webhooks
    > "$STATEDIR/requests.jsonl" 2>/dev/null || true

    # Start the autonomous daemon in the background. The daemon's heartbeat
    # worker picks up per-project scan tasks from HEARTBEAT.md (seeded on
    # first run from the [[projects]] config). No explicit "monitor" command
    # is needed: the daemon is the product.
    log "Starting OpsClaw daemon..."
    HOME="$STATEDIR" OPSCLAW_CONFIG_DIR="$STATEDIR/.opsclaw" \
        "$OPSCLAW_BIN" daemon --host 127.0.0.1 --port 0 \
        > "$STATEDIR/opsclaw.log" 2>&1 &
    echo $! > "$STATEDIR/opsclaw.pid"
    ok "OpsClaw daemon running (PID $(cat "$STATEDIR/opsclaw.pid"))"

    echo ""
    echo -e "${BOLD}Simulation environment is ready.${NC}"
    echo ""
    echo "  Inject a fault:   $0 fault memory"
    echo "  Clear faults:     $0 clear"
    echo "  View alerts:      $0 logs"
    echo "  View webhooks:    $0 webhooks"
    echo "  Show status:      $0 status"
    echo "  Tear down:        $0 down"
    echo ""
    echo "Available faults: memory, disk, load, container, restart, service, port, crisis"
}

cmd_down() {
    log "Tearing down simulation environment..."

    # Kill OpsClaw if running
    if [ -f "$STATEDIR/opsclaw.pid" ]; then
        local pid
        pid=$(cat "$STATEDIR/opsclaw.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            ok "OpsClaw daemon stopped (PID $pid)"
        fi
        rm -f "$STATEDIR/opsclaw.pid"
    fi

    # Stop Docker services
    cd "$SIMDIR"
    docker compose down -v 2>/dev/null || true

    # Clean state (keep SSH keys for faster restart)
    rm -f "$STATEDIR/opsclaw.log" "$STATEDIR/baseline.log" "$STATEDIR/requests.jsonl"
    rm -rf "$STATEDIR/.opsclaw" "$STATEDIR/.zeroclaw"
    rm -rf "$STATEDIR/snapshots"

    ok "Simulation environment stopped"
}

cmd_fault() {
    local name="${1:-}"
    if [ -z "$name" ]; then
        err "Usage: $0 fault <name>"
        echo "Available faults: memory, disk, load, container, restart, service, port, crisis"
        return 1
    fi

    inject_scenario "$name"
    echo ""
    echo -e "  ${YELLOW}Fault '${name}' injected.${NC} OpsClaw will detect it on the next heartbeat tick (~60s)."
    echo "  Watch with: $0 logs"
}

cmd_clear() {
    inject_scenario baseline
    echo ""

    # Delete the stored snapshot so the next scan re-establishes baseline
    rm -f "$STATEDIR/.opsclaw/snapshots/sim-target.json" 2>/dev/null || true

    echo -e "  ${GREEN}Cleared to healthy baseline.${NC} Next scan will re-establish baseline."
}

cmd_status() {
    echo -e "${BOLD}=== OpsClaw Simulation Status ===${NC}"
    echo ""

    # Current scenario
    local scenario
    scenario=$(docker exec "$CONTAINER_NAME" head -1 /sim/active-scenario.sh 2>/dev/null | sed 's/^# //')
    echo -e "Current scenario: ${CYAN}${scenario:-none}${NC}"

    # OpsClaw process
    if [ -f "$STATEDIR/opsclaw.pid" ] && kill -0 "$(cat "$STATEDIR/opsclaw.pid")" 2>/dev/null; then
        echo -e "OpsClaw daemon:  ${GREEN}running${NC} (PID $(cat "$STATEDIR/opsclaw.pid"))"
    else
        echo -e "OpsClaw daemon:  ${RED}not running${NC}"
    fi

    # Recent log output
    echo ""
    echo -e "${BOLD}Recent OpsClaw output:${NC}"
    if [ -f "$STATEDIR/opsclaw.log" ]; then
        tail -10 "$STATEDIR/opsclaw.log"
    else
        echo "  (no log file)"
    fi

    # Recent webhooks
    echo ""
    echo -e "${BOLD}Recent webhook notifications:${NC}"
    if [ -f "$STATEDIR/requests.jsonl" ] && [ -s "$STATEDIR/requests.jsonl" ]; then
        tail -3 "$STATEDIR/requests.jsonl" | python3 -m json.tool 2>/dev/null || tail -3 "$STATEDIR/requests.jsonl"
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
    if [ ! -f "$STATEDIR/requests.jsonl" ] || [ ! -s "$STATEDIR/requests.jsonl" ]; then
        echo "No webhook notifications captured yet."
        return 0
    fi
    # Pretty-print each JSONL line
    while IFS= read -r line; do
        echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
        echo "---"
    done < "$STATEDIR/requests.jsonl"
}

cmd_test() {
    local faults=("memory" "disk" "load" "container" "restart" "service" "port" "crisis")
    local passed=0
    local failed=0

    log "Running all scenarios..."

    # Start environment
    cmd_up

    for fault in "${faults[@]}"; do
        echo ""
        log "Testing fault: $fault"

        # Clear previous state
        > "$STATEDIR/requests.jsonl" 2>/dev/null || true

        # Inject fault
        inject_scenario "$fault"

        # Heartbeat interval is 1 minute; allow up to 90s for the daemon
        # to tick, decide, and emit a webhook.
        log "Waiting for detection (up to 90s)..."
        local detected=false
        for i in $(seq 1 90); do
            if [ -s "$STATEDIR/requests.jsonl" ]; then
                detected=true
                break
            fi
            sleep 1
        done

        if $detected; then
            ok "PASS: $fault — alert detected and notification sent"
            tail -1 "$STATEDIR/requests.jsonl"
            passed=$((passed + 1))
        else
            err "FAIL: $fault — no notification received within 90s"
            echo "OpsClaw log tail:"
            tail -5 "$STATEDIR/opsclaw.log" 2>/dev/null || true
            failed=$((failed + 1))
        fi

        # Reset to baseline for the next test and give the daemon a tick
        # to re-establish the healthy snapshot.
        inject_scenario baseline
        rm -f "$STATEDIR/.opsclaw/snapshots/sim-target.json" 2>/dev/null || true
        sleep 65
    done

    echo ""
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
    fault)     cmd_fault "${2:-}" ;;
    clear)     cmd_clear ;;
    status)    cmd_status ;;
    logs)      cmd_logs ;;
    webhooks)  cmd_webhooks ;;
    test)      cmd_test ;;
    *)
        echo "OpsClaw Simulation Environment"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  up              Start the simulation environment"
        echo "  down            Stop and clean up"
        echo "  fault <name>    Inject a fault scenario"
        echo "  clear           Clear faults, return to healthy"
        echo "  status          Show current state and recent alerts"
        echo "  logs            Tail OpsClaw daemon output"
        echo "  webhooks        Show captured webhook notifications"
        echo "  test            Run all scenarios automatically"
        echo ""
        echo "Available faults:"
        echo "  memory     Memory pressure (95% used)"
        echo "  disk       Disk full (/data at 92%)"
        echo "  load       High CPU load (load avg 12.5)"
        echo "  container  Container disappeared (api)"
        echo "  restart    Container restarted (api)"
        echo "  service    Service stopped (nginx)"
        echo "  port       Port gone (443)"
        echo "  crisis     Combined: memory + disk + container down"
        ;;
esac
