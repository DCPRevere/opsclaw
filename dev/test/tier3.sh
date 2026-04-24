#!/usr/bin/env bash
# Tier 3 (flows) is future work. Stub writes a MISSING verdict.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$ROOT/target"
cat > "$ROOT/target/tier3-verdict.json" <<'JSON'
{"tier":3,"verdict":"MISSING","reason":"tier3 not implemented in this branch"}
JSON
echo "[tier3] stub — MISSING verdict written" >&2
exit 0
