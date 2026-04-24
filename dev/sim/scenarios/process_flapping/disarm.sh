#!/usr/bin/env bash
set -euo pipefail
if [ -f /tmp/flap-driver.pid ]; then
    kill "$(cat /tmp/flap-driver.pid)" 2>/dev/null || true
    rm -f /tmp/flap-driver.pid
fi
pkill -f /tmp/flap-driver.sh 2>/dev/null || true
# Ensure myapp ends up running.
pkill -f "python3 /opt/myapp/myapp.py" 2>/dev/null || true
sleep 1
nohup python3 /opt/myapp/myapp.py >/var/log/myapp.stdout 2>&1 &
