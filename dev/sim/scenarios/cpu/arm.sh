#!/usr/bin/env bash
# CPU saturation: peg all 4 vCPUs with matrix products. Load average
# climbs into the 3–5 range within ~30s, visible in uptime, /proc/loadavg,
# top, vmstat, pidstat.
set -euo pipefail
nohup stress-ng --cpu 4 --cpu-method matrixprod --timeout 0 \
    >/tmp/stress-cpu.log 2>&1 &
echo $! > /tmp/stress-cpu.pid
sleep 2
