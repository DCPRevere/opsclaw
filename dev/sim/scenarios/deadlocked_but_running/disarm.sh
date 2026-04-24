#!/usr/bin/env bash
set -euo pipefail
if [ -f /var/run/myapp.pid ]; then
    kill -CONT "$(cat /var/run/myapp.pid)" 2>/dev/null || true
fi
