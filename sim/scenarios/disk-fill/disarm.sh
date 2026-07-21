#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" rm -f /data/fill.bin

used_pct="$(docker exec "$SIM_CONTAINER" sh -c "df -P /data | awk 'NR==2{gsub(/%/,\"\",\$5); print \$5}'")"
echo "disk-fill: disarmed, /data now ${used_pct}% used"

if [ "$used_pct" -gt 20 ]; then
    echo "disk-fill: FAIL — /data still ${used_pct}% used after disarm" >&2
    exit 1
fi
