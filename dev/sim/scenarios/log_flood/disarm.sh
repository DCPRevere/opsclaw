#!/usr/bin/env bash
set -euo pipefail
if [ -f /tmp/log-flood.pid ]; then
    kill "$(cat /tmp/log-flood.pid)" 2>/dev/null || true
    rm -f /tmp/log-flood.pid
fi
pkill -f /tmp/log-flood.sh 2>/dev/null || true
rm -f /var/log/test.log
