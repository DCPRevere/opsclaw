#!/usr/bin/env bash
# Port closed: myapp is running (ps shows it) but iptables drops all
# traffic to port 8080. A listener check shows the port up; an actual
# HTTP probe times out. Classic half-working-service fault.
set -euo pipefail
iptables -I INPUT 1 -p tcp --dport 8080 -j DROP || true
