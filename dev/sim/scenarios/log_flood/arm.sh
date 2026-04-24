#!/usr/bin/env bash
# Log flood: spew 4KB lines to /var/log/test.log at full speed. Over a
# minute this grows the file by hundreds of MB, visible in du/ls -la.
set -euo pipefail
cat >/tmp/log-flood.sh <<'EOF'
#!/usr/bin/env bash
while true; do
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 4096 >>/var/log/test.log
    printf '\n' >>/var/log/test.log
done
EOF
chmod +x /tmp/log-flood.sh
nohup /tmp/log-flood.sh >/dev/null 2>&1 &
echo $! > /tmp/log-flood.pid
