#!/usr/bin/env bash
set -euo pipefail
nohup python3 /opt/myapp/myapp.py >/var/log/myapp.stdout 2>&1 &
# Wait briefly for the socket to come back.
for _ in $(seq 1 10); do
    ss -tln 2>/dev/null | grep -q ':8080' && break
    sleep 0.5
done
