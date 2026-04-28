#!/usr/bin/env bash
#
# Slot lifecycle for the parallel tier 2 harness.
#
# A "slot" is an isolated testing environment: one sim-target + one
# webhook-sink + one OpsClaw daemon, each bound to slot-specific ports
# and state directories. Slots do not share docker networks, filesystems,
# or SSH keys.
#
#   slot.sh up <slot_n>          Bring a slot up, wait for SSH, start daemon
#   slot.sh down <slot_n>        Tear the slot down, kill daemon
#   slot.sh exec <slot_n> <cmd>  docker exec into the slot's sim-target
#   slot.sh state-dir <slot_n>   Print STATEDIR for the slot (harness uses this)
#
# Slot N uses:
#   SSH port    = 2222 + N
#   Webhook port= 9999 + N
#   Container names: opsclaw-sim-target-<N>, opsclaw-webhook-sink-<N>
#   STATEDIR    = $SIMDIR/.state/slot-<N>
#
# The harness never calls ./sim.sh; it drives slots directly through
# this script. ./sim.sh still works for a single-developer run against
# slot 0 via its own compose setup.

set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
SIMDIR="$(cd "$HARNESS_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SIMDIR/../.." && pwd)"
OPSCLAW_BIN="$REPO_ROOT/target/debug/opsclaw"

# Load dev/sim/.env for OPENAI_API_KEY. Same parser as sim.sh.
if [ -f "$SIMDIR/.env" ]; then
    while IFS= read -r __line || [ -n "$__line" ]; do
        case "$__line" in ''|'#'*) continue ;; esac
        if [[ "$__line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
            if [[ "$v" =~ ^\"(.*)\"$ ]] || [[ "$v" =~ ^\'(.*)\'$ ]]; then v="${BASH_REMATCH[1]}"; fi
            export "$k=$v"
        fi
    done < "$SIMDIR/.env"
    unset __line
fi

SIM_IMAGE="${OPSCLAW_SIM_IMAGE:-opsclaw-sim-target}"
SINK_IMAGE="${OPSCLAW_SIM_SINK_IMAGE:-opsclaw-sim-webhook-sink}"

log() { echo "[slot:$SLOT] $*" >&2; }

state_dir() {
    local n="$1"
    echo "$SIMDIR/.state/slot-$n"
}

ensure_images() {
    # Build once; all slots share the same images.
    if ! docker image inspect "$SIM_IMAGE" >/dev/null 2>&1; then
        (cd "$SIMDIR/sim-target" && docker build -t "$SIM_IMAGE" . >&2)
    fi
    if ! docker image inspect "$SINK_IMAGE" >/dev/null 2>&1; then
        (cd "$SIMDIR/webhook-sink" && docker build -t "$SINK_IMAGE" . >&2)
    fi
}

cmd_state_dir() { state_dir "$1"; }

cmd_up() {
    local n="$1"
    SLOT="$n"
    local ssh_port=$((2222 + n))
    local webhook_port=$((9999 + n))
    local net="opsclaw-sim-slot-$n"
    local target_name="opsclaw-sim-target-$n"
    local sink_name="opsclaw-sim-sink-$n"
    local sd; sd=$(state_dir "$n")

    # When OPSCLAW_REPLAY_LLM_URL is set, the daemon talks to the local
    # replay-llm scaffold (dev/sim/replay-llm/server.py) instead of
    # OpenAI. The API key check is then optional — the replay server
    # ignores it. See dev/sim/replay-llm/README.md for status.
    if [ -z "${OPSCLAW_REPLAY_LLM_URL:-}" ] && [ -z "${OPENAI_API_KEY:-}" ]; then
        echo "OPENAI_API_KEY not set (dev/sim/.env or export); " \
             "or set OPSCLAW_REPLAY_LLM_URL to use the local replay LLM" >&2
        return 1
    fi

    mkdir -p "$sd/.opsclaw" "$sd/.zeroclaw"

    # SSH keypair per slot so one slot's known_hosts doesn't pollute another.
    local ssh_key="$sd/sim_key"
    if [ ! -f "$ssh_key" ]; then
        ssh-keygen -t ed25519 -f "$ssh_key" -N "" -q
    fi
    local pubkey; pubkey=$(cat "${ssh_key}.pub")

    ensure_images

    # Network (isolated per slot).
    docker network create --driver bridge "$net" >/dev/null 2>&1 || true

    # Webhook sink. Binds to 127.0.0.1:$webhook_port; writes to
    # $sd/requests.jsonl (mounted).
    : > "$sd/requests.jsonl"
    docker run -d --rm \
        --name "$sink_name" \
        --network "$net" \
        -p "127.0.0.1:$webhook_port:9999" \
        -e PORT=9999 \
        -v "$sd:/data" \
        "$SINK_IMAGE" >/dev/null

    # Sim-target under gVisor. stress-ng / fallocate / tc etc. run
    # inside; cgroup limits enforced; Sentry serves /proc.
    docker run -d --rm \
        --name "$target_name" \
        --runtime=runsc \
        --network "$net" \
        -p "127.0.0.1:$ssh_port:2222" \
        --memory 8g --memory-swap 8g --cpus 4 \
        --cap-add NET_ADMIN --cap-add SYS_ADMIN \
        --tmpfs /data:size=200m \
        -e "AUTHORIZED_KEY=$pubkey" \
        -e SSH_PORT=2222 \
        "$SIM_IMAGE" >/dev/null

    # Wait for SSH.
    log "waiting for SSH on 127.0.0.1:$ssh_port..."
    local i
    for i in $(seq 1 30); do
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o ConnectTimeout=1 -o LogLevel=ERROR \
               -i "$ssh_key" -p "$ssh_port" opsclaw@127.0.0.1 "true" &>/dev/null; then
            break
        fi
        sleep 1
    done

    # Config — same shape as sim.sh, but slot-specific ports + paths.
    local key_content; key_content=$(cat "$ssh_key")
    local provider_extra=""
    if [ -n "${OPSCLAW_REPLAY_LLM_URL:-}" ]; then
        provider_extra="base_url = \"$OPSCLAW_REPLAY_LLM_URL\""
    fi
    cat > "$sd/.opsclaw/config.toml" <<TOML
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
$provider_extra

[channels.webhook]
enabled = true
port = 0
send_url = "http://127.0.0.1:$webhook_port/alerts"
send_method = "POST"

[notifications]
webhook_url = "http://127.0.0.1:$webhook_port/alerts"
min_severity = "warning"

[observability]
backend = "log"
# Tier 2 reads this JSONL stream for richer assertions (tool calls,
# model replies, turn boundaries) — beyond what the webhook sink sees.
runtime_trace_mode = "rolling"
runtime_trace_max_entries = 5000
runtime_trace_path = "$sd/runtime-trace.jsonl"

[[targets]]
name = "sim-target"
type = "ssh"
host = "127.0.0.1"
port = $ssh_port
user = "opsclaw"
autonomy = "dry-run"
key_secret = '''
$key_content
'''
TOML

    cat > "$sd/.zeroclaw/config.toml" <<'TOML'
schema_version = 2

[secrets]
encrypt = false
TOML

    # OpsClaw daemon — gateway on random port, state in slot dir.
    # Slots pick from a different set of gateway ports implicitly by
    # asking the kernel for 0; the --port 0 path has been working.
    HOME="$sd" OPSCLAW_CONFIG_DIR="$sd/.opsclaw" \
        ZEROCLAW_API_KEY="$OPENAI_API_KEY" \
        "$OPSCLAW_BIN" daemon --host 127.0.0.1 --port 0 \
        > "$sd/opsclaw.log" 2>&1 &
    echo $! > "$sd/opsclaw.pid"
    log "daemon pid=$(cat "$sd/opsclaw.pid")"
}

cmd_down() {
    local n="$1"
    SLOT="$n"
    local target_name="opsclaw-sim-target-$n"
    local sink_name="opsclaw-sim-sink-$n"
    local net="opsclaw-sim-slot-$n"
    local sd; sd=$(state_dir "$n")

    if [ -f "$sd/opsclaw.pid" ]; then
        local pid; pid=$(cat "$sd/opsclaw.pid")
        if kill -0 "$pid" 2>/dev/null; then kill "$pid"; fi
        rm -f "$sd/opsclaw.pid"
    fi

    docker rm -f "$target_name" "$sink_name" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true

    # Keep logs + state for post-mortem; harness may archive them.
}

cmd_exec() {
    local n="$1"; shift
    docker exec -i "opsclaw-sim-target-$n" "$@"
}

# ── main ────────────────────────────────────────────────────────────

SLOT="?"
case "${1:-}" in
    up)         shift; cmd_up "$@" ;;
    down)       shift; cmd_down "$@" ;;
    exec)       shift; cmd_exec "$@" ;;
    state-dir)  shift; cmd_state_dir "$@" ;;
    *) echo "usage: $0 {up|down|exec|state-dir} <slot> [args]" >&2; exit 2 ;;
esac
