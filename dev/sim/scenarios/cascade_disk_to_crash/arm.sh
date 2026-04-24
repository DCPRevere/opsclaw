#!/usr/bin/env bash
# Cascade: fill /data to 99%, then also SIGSTOP myapp (which in a real
# SRE incident would crash after failing to write). We present two
# concurrent faults and expect the agent to report both or their link.
set -euo pipefail
rm -f /data/big
fallocate -l 195M /data/big
sleep 1
if [ -f /var/run/myapp.pid ]; then
    kill -STOP "$(cat /var/run/myapp.pid)" 2>/dev/null || true
fi
