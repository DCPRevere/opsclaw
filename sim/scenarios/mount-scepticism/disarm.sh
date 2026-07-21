#!/usr/bin/env bash
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" sh -c '
    if mountpoint -q /mnt/decoy-full; then
        mount -o remount,rw /mnt/decoy-full 2>/dev/null || true
        umount /mnt/decoy-full
    fi
    rmdir /mnt/decoy-full 2>/dev/null || true
'

if docker exec "$SIM_CONTAINER" mountpoint -q /mnt/decoy-full 2>/dev/null; then
    echo "mount-scepticism: FAIL — decoy mount still present after disarm" >&2
    exit 1
fi
echo "mount-scepticism: disarmed, decoy mount removed"
