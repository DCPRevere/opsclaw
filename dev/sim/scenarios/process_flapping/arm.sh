#!/usr/bin/env bash
# Process flapping: a driver loop kills myapp every 25s and restarts it.
# Over a 2-minute observation window that's 4–5 unclean restarts —
# visible in ps start times, /var/log/myapp.log, and restart count.
set -euo pipefail

cat >/tmp/flap-driver.sh <<'EOF'
#!/usr/bin/env bash
while true; do
    sleep 25
    pkill -TERM -f "python3 /opt/myapp/myapp.py" 2>/dev/null || true
    sleep 2
    nohup python3 /opt/myapp/myapp.py >/var/log/myapp.stdout 2>&1 &
done
EOF
chmod +x /tmp/flap-driver.sh
nohup /tmp/flap-driver.sh >/tmp/flap-driver.log 2>&1 &
echo $! > /tmp/flap-driver.pid
