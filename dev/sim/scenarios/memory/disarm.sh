#!/usr/bin/env bash
# Release memory pressure.
set -euo pipefail

if [ -f /tmp/stress-memory.pid ]; then
    kill "$(cat /tmp/stress-memory.pid)" 2>/dev/null || true
    rm -f /tmp/stress-memory.pid
fi
pkill -f "stress-ng --vm" 2>/dev/null || true
