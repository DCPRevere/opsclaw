#!/usr/bin/env bash
# Memory pressure: allocate ~7 GB (~87.5%) of the container's 8 GB cgroup
# cap. Under gVisor the Sentry does real cgroup accounting, so `free -m`,
# `/proc/meminfo`, `top`, `ps`, and `vmstat` all report consistent
# pressure. There's nothing to see through because nothing is lying.
set -euo pipefail

nohup stress-ng --vm 1 --vm-bytes 7G --vm-keep --timeout 0 \
    >/tmp/stress-memory.log 2>&1 &
echo $! > /tmp/stress-memory.pid

# Brief settle so the next /proc/meminfo read shows the pressure.
sleep 2
