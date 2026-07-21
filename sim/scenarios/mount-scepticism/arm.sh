#!/usr/bin/env bash
# mount-scepticism — REQUIREMENT (brief §9 / DESIGN.md "environment
# scepticism": "gVisor's host-bind mounts make df lie" / "evaluate writable
# mounts, not every mount"). Arms a DECOY read-only bind mount that reports
# as full/unhealthy via df, while every actually-writable mount on the
# target stays healthy. must_notify is false: the daemon must not be fooled
# by the decoy and must reason about writability, not raw df% across all
# mounts.
#
# Mechanism: bind-mount a small tmpfs at /mnt/decoy-full and fill it
# completely (0 bytes free -> 100% used by df), then remount it read-only.
# /data (the real writable mount, see target.Dockerfile) is left untouched
# and healthy. A daemon that alerts on "some mount is at 100%" without
# checking writability/relevance fails this scenario; one that filters to
# writable, in-use mounts stays silent correctly.
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" sh -c '
    set -e
    mkdir -p /mnt/decoy-full
    mount -t tmpfs -o size=8m tmpfs /mnt/decoy-full
    dd if=/dev/zero of=/mnt/decoy-full/filler bs=1M count=8 2>/dev/null || true
    mount -o remount,ro /mnt/decoy-full
'

decoy_pct="$(docker exec "$SIM_CONTAINER" sh -c "df -P /mnt/decoy-full | awk 'NR==2{gsub(/%/,\"\",\$5); print \$5}'")"
data_pct="$(docker exec "$SIM_CONTAINER" sh -c "df -P /data | awk 'NR==2{gsub(/%/,\"\",\$5); print \$5}'")"
echo "mount-scepticism: armed — /mnt/decoy-full=${decoy_pct}% (ro, decoy) /data=${data_pct}% (rw, real)"

if [ "$decoy_pct" -lt 90 ]; then
    echo "mount-scepticism: FAIL — decoy mount did not fill (${decoy_pct}%)" >&2
    exit 1
fi
if [ "$data_pct" -gt 20 ]; then
    echo "mount-scepticism: FAIL — /data unexpectedly not healthy (${data_pct}%)" >&2
    exit 1
fi
