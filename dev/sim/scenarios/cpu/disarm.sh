#!/usr/bin/env bash
set -euo pipefail
if [ -f /tmp/stress-cpu.pid ]; then
    kill "$(cat /tmp/stress-cpu.pid)" 2>/dev/null || true
    rm -f /tmp/stress-cpu.pid
fi
pkill -f "stress-ng --cpu" 2>/dev/null || true
