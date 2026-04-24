#!/usr/bin/env bash
# Deadlocked-but-running: SIGSTOP the myapp process. ps shows it
# running (state T = stopped, subtle), netstat shows port 8080 bound
# (kernel keeps the socket until the process dies), but any HTTP probe
# hangs until timeout. Classic "looks up, isn't".
set -euo pipefail
if [ -f /var/run/myapp.pid ]; then
    kill -STOP "$(cat /var/run/myapp.pid)" 2>/dev/null || true
fi
