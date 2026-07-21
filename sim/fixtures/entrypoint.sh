#!/usr/bin/env bash
# sim/fixtures/entrypoint.sh — container entrypoint for the sim target image.
# Generates fresh host keys and installs the run's authorized_keys (mounted
# by sim/run.sh at /run/opsclaw-sim/authorized_keys), then hands off to
# supervisord as PID 1 so sshd + the fake services are supervised together.
set -euo pipefail

ssh-keygen -A >/dev/null 2>&1 || true

if [ -f /run/opsclaw-sim/authorized_keys ]; then
    install -m 600 -o root -g root /run/opsclaw-sim/authorized_keys /root/.ssh/authorized_keys
fi

mkdir -p /var/log/opsclaw-sim

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
