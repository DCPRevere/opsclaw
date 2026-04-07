#!/bin/bash
set -e

# Inject the authorized key if provided
if [ -n "$AUTHORIZED_KEY" ]; then
    echo "$AUTHORIZED_KEY" > /home/opsclaw/.ssh/authorized_keys
    chmod 600 /home/opsclaw/.ssh/authorized_keys
    chown opsclaw:opsclaw /home/opsclaw/.ssh/authorized_keys
fi

# Generate host keys if missing
ssh-keygen -A

# Start sshd in foreground on the configured port (default 2222 to avoid conflicts)
SSH_PORT="${SSH_PORT:-2222}"
exec /usr/sbin/sshd -D -e -p "$SSH_PORT"
