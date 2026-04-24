#!/usr/bin/env bash
# Service stopped: kill the myapp sentinel service cleanly. The pidfile
# remains but the process is gone and port 8080 stops listening.
set -euo pipefail
if [ -f /var/run/myapp.pid ]; then
    kill -TERM "$(cat /var/run/myapp.pid)" 2>/dev/null || true
    # Give it a second to drop the socket; remove the pidfile so
    # "file present, process absent" doesn't confuse the agent.
    sleep 1
    rm -f /var/run/myapp.pid
fi
pkill -TERM -f "python3 /opt/myapp/myapp.py" 2>/dev/null || true
