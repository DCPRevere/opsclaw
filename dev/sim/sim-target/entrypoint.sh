#!/bin/bash
#
# sim-target entrypoint.
#
# Under gVisor (`runtime: runsc` in docker-compose), the Sentry kernel
# serves /proc and /sys from the sandbox's own accounting, so there is
# nothing for us to fake or bind-mount — cgroup limits are visible
# directly. Just configure SSH and hand off to sshd.
set -e

# Inject the authorized key if provided.
if [ -n "$AUTHORIZED_KEY" ]; then
    echo "$AUTHORIZED_KEY" > /home/opsclaw/.ssh/authorized_keys
    chmod 600 /home/opsclaw/.ssh/authorized_keys
    chown opsclaw:opsclaw /home/opsclaw/.ssh/authorized_keys
fi

# Generate host keys if missing.
ssh-keygen -A

# Start the "myapp" sentinel service in the background so baseline
# scenarios see a realistic long-running service bound to port 8080.
# Scenarios stop, crash, or iptables-block it to produce faults.
mkdir -p /var/run
nohup python3 /opt/myapp/myapp.py >/var/log/myapp.stdout 2>&1 &
echo "[sim-target] myapp started (pid $(cat /var/run/myapp.pid 2>/dev/null || echo ?))"

# Start sshd in foreground on the configured port (default 2222).
SSH_PORT="${SSH_PORT:-2222}"
exec /usr/sbin/sshd -D -e -p "$SSH_PORT"
