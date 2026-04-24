#!/usr/bin/env bash
#
# Top-level test dispatcher. Called by humans and agents alike.
#
# Usage:
#   dev/test.sh tier1        Tier 1: component harness (Rust integration tests)
#   dev/test.sh tier2 [args] Tier 2: sim harness (dev/sim/harness/run.sh)
#   dev/test.sh tier3        Tier 3: flow harness
#   dev/test.sh ready        Runs tier1 + tier2 + tier3, prints combined JSON
#
# Exit 0 on PASS, non-zero on FAIL. Verdicts are written to
# target/tier{1,2,3}-verdict.json and target/ready-verdict.json.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cmd="${1:-}"; shift || true

case "$cmd" in
    tier1)
        exec "$ROOT/dev/test/tier1.sh" "$@"
        ;;
    tier2)
        exec "$ROOT/dev/sim/harness/run.sh" "$@"
        ;;
    tier3)
        exec "$ROOT/dev/test/tier3.sh" "$@"
        ;;
    ready)
        # Run all three, collect verdicts, emit composite. Tier 1 is a
        # cargo-test passthrough (exit code only); tier 2 and 3 emit
        # structured JSON for per-scenario results.
        mkdir -p "$ROOT/target"
        overall=0

        tier1_rc=0
        "$ROOT/dev/test/tier1.sh" "$@" || tier1_rc=$?
        [[ $tier1_rc -eq 0 ]] || overall=1

        "$ROOT/dev/sim/harness/run.sh" --bring-up "$@" || overall=1
        "$ROOT/dev/test/tier3.sh" "$@" || overall=1

        python3 - "$ROOT/target" "$tier1_rc" <<'PY' || overall=1
import json, os, sys
root = sys.argv[1]
tier1_rc = int(sys.argv[2])
def read(path):
    try:
        return json.load(open(os.path.join(root, path)))
    except Exception:
        return {"verdict": "MISSING"}
combined = {
    "verdict": "PASS",
    "tier1": {"verdict": "PASS" if tier1_rc == 0 else "FAIL", "exit_code": tier1_rc},
    "tier2": read("tier2-verdict.json"),
    "tier3": read("tier3-verdict.json"),
}
for k in ("tier1", "tier2", "tier3"):
    if combined[k].get("verdict") != "PASS":
        combined["verdict"] = "FAIL"
json.dump(combined, open(os.path.join(root, "ready-verdict.json"), "w"), indent=2)
print(json.dumps(combined, indent=2))
PY
        exit "$overall"
        ;;
    ""|help|-h|--help)
        sed -n '3,12p' "$0" | sed 's/^# //;s/^#$//'
        ;;
    *)
        echo "unknown subcommand: $cmd" >&2
        exit 2
        ;;
esac
