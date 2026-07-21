#!/usr/bin/env bash
# mem-pressure — allocate and dirty most of the container's available
# memory via stress-ng's vm stressor. Uses a percentage of available memory
# (--vm-bytes 85%) rather than a fixed size so this is robust across
# differently-sized CI/dev hosts.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" pkill -x stress-ng 2>/dev/null || true
docker exec -d "$SIM_CONTAINER" stress-ng --vm 2 --vm-bytes 85% --vm-keep --timeout 0

sleep 4
mem_line="$(docker exec "$SIM_CONTAINER" sh -c "free -m | awk '/Mem:/{printf \"%d/%d\", \$3, \$2}'")"
echo "mem-pressure: armed, used/total MB = ${mem_line}"

docker exec "$SIM_CONTAINER" pgrep -x stress-ng >/dev/null || {
    echo "mem-pressure: FAIL — stress-ng is not running after arm" >&2
    exit 1
}
