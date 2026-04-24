#!/usr/bin/env bash
# Memory pressure: allocate ~7 GB (87.5%) of the container's 8 GB cgroup
# cap with stress-ng. The kernel cgroup memory accounting is real, so
# `free -m`, `/proc/meminfo`, `top`, `ps`, and `vmstat` all report the
# pressure consistently. The agent cannot see through this by reading
# any particular file — there is no "real" reading, only the cgroup's.
set -euo pipefail

case "${1:-arm}" in
    arm)
        # --vm 1 : one worker
        # --vm-bytes 7G : allocate 7 GB
        # --vm-keep : touch memory continuously so kernel can't reclaim
        # --timeout 0 : no auto-stop; we control with disarm
        # & : background, so this script returns immediately
        nohup stress-ng --vm 1 --vm-bytes 7G --vm-keep --timeout 0 \
            >/tmp/stress-memory.log 2>&1 &
        echo $! > /tmp/stress-memory.pid
        # Brief settle so the next /proc/meminfo read shows the pressure.
        sleep 2
        ;;
    disarm)
        if [ -f /tmp/stress-memory.pid ]; then
            kill "$(cat /tmp/stress-memory.pid)" 2>/dev/null || true
            rm -f /tmp/stress-memory.pid
        fi
        # Belt and braces.
        pkill -f "stress-ng --vm" 2>/dev/null || true
        ;;
    *)
        echo "usage: $0 {arm|disarm}" >&2
        exit 2
        ;;
esac
