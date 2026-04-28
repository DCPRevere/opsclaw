#!/usr/bin/env bash
#
# Tier 2 orchestrator — parallel.
#
# Allocates a pool of N isolated slots via slot.sh, pops scenarios from
# a queue, assigns each to a free slot, and runs arm/dedup/disarm under
# that slot's sim-target + webhook-sink + daemon. Each slot has its own
# requests.jsonl so alert counts stay clean.
#
# Usage:
#   run.sh [--only NAME] [--skip PATTERN] [--parallel N]
#          [--bring-up] [--no-tear-down]
#
#   --parallel N   How many slots to run concurrently (default 1).
#                  Each slot costs ~1 GB RAM, 1 CPU + LLM API concurrency.
#   --only         Run one scenario.
#   --skip         Shell glob of scenarios to skip (e.g. '*cascade*').
#   --bring-up     Bring slots up inside the harness; tear them down
#                  unless --no-tear-down is given.
#
# Exit: 0 if every scenario PASSes, 1 otherwise.

set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
SIMDIR="$(cd "$HARNESS_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SIMDIR/../.." && pwd)"
OUT="$REPO_ROOT/target/tier2-verdict.json"
SLOT_SH="$HARNESS_DIR/slot.sh"
ASSERT="$HARNESS_DIR/assert_phase.py"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[tier2]${NC} $*" >&2; }
ok()   { echo -e "${GREEN}[tier2]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[tier2]${NC} $*" >&2; }
err()  { echo -e "${RED}[tier2]${NC} $*" >&2; }

# ── argv ────────────────────────────────────────────────────────────
only=""
skip=""
parallel=1
bring_up=false
no_tear_down=false

while [ $# -gt 0 ]; do
    case "$1" in
        --only)         only="$2";           shift 2 ;;
        --skip)         skip="$2";           shift 2 ;;
        --parallel)     parallel="$2";       shift 2 ;;
        --bring-up)     bring_up=true;       shift ;;
        --no-tear-down) no_tear_down=true;   shift ;;
        *) err "unknown arg: $1"; exit 2 ;;
    esac
done

if ! [[ "$parallel" =~ ^[1-9][0-9]*$ ]]; then
    err "--parallel must be a positive integer"
    exit 2
fi

# ── helpers ─────────────────────────────────────────────────────────

count_alerts() {
    local req="$1"
    [ -s "$req" ] || { echo 0; return; }
    python3 -c "
import json
n = 0
for line in open('$req'):
    try:
        e = json.loads(line)
        p = e.get('payload', e)
        if isinstance(p, dict) and p.get('type') == 'opsclaw.alert':
            n += 1
    except Exception:
        pass
print(n)
"
}

assert_phase() {
    local scenario_dir="$1" phase="$2" baseline="$3" req="$4" trace="$5"
    local trace_arg=()
    [ -n "$trace" ] && [ -f "$trace" ] && trace_arg=(--trace "$trace")
    python3 "$ASSERT" \
        "$scenario_dir/expected.json" "$req" "$phase" \
        --baseline-count "$baseline" \
        "${trace_arg[@]}"
}

expected_int() {
    local f="$1" path="$2" default="$3"
    python3 -c "
import json
try:
    d = json.load(open('$f'))
    for k in '$path'.split('.'):
        d = d[k]
    print(int(d))
except Exception:
    print($default)
"
}

# Run one scenario on one slot. Writes the scenario verdict as a JSON
# line to $VERDICTS_DIR/$name.json. Returns 0 PASS / 1 FAIL.
run_scenario() {
    local name="$1" slot="$2"
    local sd; sd=$("$SLOT_SH" state-dir "$slot")
    local req="$sd/requests.jsonl"
    local trace="$sd/runtime-trace.jsonl"
    local scenario_dir="$SIMDIR/scenarios/$name"

    log "[$name] slot=$slot starting"

    local has_arm has_dedup has_disarm
    has_arm=$(python3 -c "import json;print('phase_arm' in json.load(open('$scenario_dir/expected.json')))")
    has_dedup=$(python3 -c "import json;print('phase_dedup' in json.load(open('$scenario_dir/expected.json')))")
    has_disarm=$(python3 -c "import json;print('phase_disarm' in json.load(open('$scenario_dir/expected.json')))")

    local baseline_before; baseline_before=$(count_alerts "$req")
    local verdicts=()
    local scenario_pass=true

    # arm ───────────────────────────────────────────────────────────
    if [ "$has_arm" = "True" ]; then
        local arm_window; arm_window=$(expected_int "$scenario_dir/expected.json" "phase_arm.within_seconds" 150)
        if [ -f "$scenario_dir/arm.sh" ]; then
            "$SLOT_SH" exec "$slot" bash -s < "$scenario_dir/arm.sh" || warn "[$name] arm.sh rc!=0"
        fi
        local i
        for i in $(seq 1 "$arm_window"); do
            [ "$(count_alerts "$req")" -gt "$baseline_before" ] && break
            sleep 1
        done
        local j
        j=$(assert_phase "$scenario_dir" phase_arm "$baseline_before" "$req" "$trace")
        local rc=$?
        verdicts+=("\"arm\":$j")
        [ $rc -ne 0 ] && scenario_pass=false
        log "[$name] phase_arm: $j"
    fi

    # dedup ─────────────────────────────────────────────────────────
    if [ "$has_dedup" = "True" ]; then
        local dedup_wait; dedup_wait=$(expected_int "$scenario_dir/expected.json" "phase_dedup.wait_seconds" 75)
        local baseline_after_arm; baseline_after_arm=$(count_alerts "$req")
        sleep "$dedup_wait"
        local j
        j=$(assert_phase "$scenario_dir" phase_dedup "$baseline_after_arm" "$req" "$trace")
        local rc=$?
        verdicts+=("\"dedup\":$j")
        [ $rc -ne 0 ] && scenario_pass=false
        log "[$name] phase_dedup: $j"
    fi

    # disarm ────────────────────────────────────────────────────────
    if [ "$has_disarm" = "True" ]; then
        local disarm_window; disarm_window=$(expected_int "$scenario_dir/expected.json" "phase_disarm.within_seconds" 150)
        local baseline_after_dedup; baseline_after_dedup=$(count_alerts "$req")
        if [ -f "$scenario_dir/disarm.sh" ]; then
            "$SLOT_SH" exec "$slot" bash -s < "$scenario_dir/disarm.sh" || warn "[$name] disarm.sh rc!=0"
        fi
        sleep "$disarm_window"
        local j
        j=$(assert_phase "$scenario_dir" phase_disarm "$baseline_after_dedup" "$req" "$trace")
        local rc=$?
        verdicts+=("\"disarm\":$j")
        [ $rc -ne 0 ] && scenario_pass=false
        log "[$name] phase_disarm: $j"
    fi

    local vstr
    vstr=$([ "$scenario_pass" = true ] && echo PASS || echo FAIL)
    if $scenario_pass; then ok "[$name] $vstr (slot=$slot)"; else err "[$name] $vstr (slot=$slot)"; fi

    local inner; inner=$(IFS=,; echo "${verdicts[*]}")
    printf '{"name":"%s","verdict":"%s","slot":%d,%s}\n' "$name" "$vstr" "$slot" "$inner" \
        > "$VERDICTS_DIR/$name.json"

    [ "$scenario_pass" = true ]
}

# ── main ────────────────────────────────────────────────────────────

START=$(date +%s)
mkdir -p "$(dirname "$OUT")"
VERDICTS_DIR=$(mktemp -d)
trap 'rm -rf "$VERDICTS_DIR"' EXIT

# Ensure opsclaw binary is built once; slots spawn daemons from it.
if [ ! -x "$REPO_ROOT/target/debug/opsclaw" ]; then
    log "building opsclaw..."
    (cd "$REPO_ROOT" && cargo build -p opsclaw 2>&1 | tail -3) >&2
fi

# Gather scenarios.
queue=()
for edir in "$SIMDIR"/scenarios/*/; do
    name=$(basename "$edir")
    [ -f "$edir/expected.json" ] || continue
    if [ -n "$only" ] && [ "$name" != "$only" ]; then continue; fi
    if [ -n "$skip" ] && [[ "$name" == $skip ]]; then continue; fi
    queue+=("$name")
done

TOTAL=${#queue[@]}
if [ "$TOTAL" -eq 0 ]; then
    err "no scenarios selected"
    exit 2
fi

# Cap parallelism to #scenarios so we don't bring up idle slots.
[ "$parallel" -gt "$TOTAL" ] && parallel="$TOTAL"

log "running $TOTAL scenario(s) with parallelism $parallel"

# Bring up slots.
if $bring_up; then
    log "bringing $parallel slot(s) up..."
    for ((s=0; s<parallel; s++)); do
        "$SLOT_SH" up "$s" &
    done
    wait
    ok "all slots up"
fi

# Queue + dispatcher.
next=0
declare -A slot_pid=()   # slot_n -> worker pid
declare -A slot_name=()  # slot_n -> scenario name

launch() {
    local slot="$1" name="$2"
    slot_name[$slot]="$name"
    (
        run_scenario "$name" "$slot"
    ) &
    slot_pid[$slot]=$!
}

# Initial fill.
while [ "$next" -lt "$TOTAL" ] && [ "${#slot_pid[@]}" -lt "$parallel" ]; do
    s=${#slot_pid[@]}
    launch "$s" "${queue[$next]}"
    next=$((next + 1))
done

# As workers finish, assign the next scenario to the freed slot.
while [ "${#slot_pid[@]}" -gt 0 ]; do
    for s in "${!slot_pid[@]}"; do
        if ! kill -0 "${slot_pid[$s]}" 2>/dev/null; then
            wait "${slot_pid[$s]}" 2>/dev/null
            unset slot_pid[$s]
            unset slot_name[$s]
            if [ "$next" -lt "$TOTAL" ]; then
                launch "$s" "${queue[$next]}"
                next=$((next + 1))
            fi
        fi
    done
    sleep 2
done

# Aggregate verdicts.
python3 - "$VERDICTS_DIR" "$OUT" "$((($(date +%s)) - START))" "$TOTAL" <<'PY'
import json, os, sys
vdir, out, duration, total = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
scenarios = {}
failed = 0
for fname in sorted(os.listdir(vdir)):
    if not fname.endswith(".json"): continue
    d = json.load(open(os.path.join(vdir, fname)))
    scenarios[d["name"]] = d
    if d.get("verdict") != "PASS":
        failed += 1
verdict = "PASS" if failed == 0 else "FAIL"
json.dump({
    "tier": 2,
    "verdict": verdict,
    "scenarios": scenarios,
    "total": total,
    "failed": failed,
    "duration_s": duration,
}, open(out, "w"), indent=2)
print(json.dumps({"verdict": verdict, "passed": total - failed, "failed": failed, "duration_s": duration}))
PY

if $bring_up && ! $no_tear_down; then
    log "tearing slots down..."
    for ((s=0; s<parallel; s++)); do
        "$SLOT_SH" down "$s" &
    done
    wait
fi

[ "$(python3 -c "import json;print(json.load(open('$OUT'))['verdict'])")" = PASS ]
