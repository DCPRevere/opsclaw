#!/usr/bin/env bash
# disk-fill — fill the writable /data mount close to capacity via
# stress-ng's hdd stressor, which writes and deletes files in a loop; we
# instead use `fallocate` for a deterministic one-shot fill so the fault is
# stable for the daemon to observe, rather than fluctuating write/delete
# churn. Fills /data (a dedicated writable dir, see target.Dockerfile) to
# avoid wedging the container's own root-fs writes (sshd, supervisord logs).
set -euo pipefail
: "${SIM_CONTAINER:?run via sim/run.sh, or export SIM_CONTAINER=<name>}"

docker exec "$SIM_CONTAINER" rm -f /data/fill.bin

# Compute 90% of /data's available space and fill it.
avail_kb="$(docker exec "$SIM_CONTAINER" sh -c "df -k /data | awk 'NR==2{print \$4}'")"
fill_kb=$(( avail_kb * 90 / 100 ))

# Safety ceiling (defence in depth). /data is a size-capped tmpfs (run.sh,
# ~200MB), so avail should be small. If it is NOT — e.g. the tmpfs cap was
# lost and df is reporting the HOST filesystem — refuse rather than fallocate
# a fraction of the whole machine. This is the guard that would have stopped
# the host-disk-wedge: a disk-fill target must be small and dedicated.
: "${SIM_DISKFILL_MAX_KB:=524288}"   # 512 MiB hard ceiling
if [ "$fill_kb" -gt "$SIM_DISKFILL_MAX_KB" ]; then
    echo "disk-fill: REFUSING — /data reports ${avail_kb}KB available, fill of ${fill_kb}KB" \
         "exceeds the ${SIM_DISKFILL_MAX_KB}KB ceiling. /data is almost certainly NOT the" \
         "size-capped tmpfs it must be (df is likely reporting the host fs). Fix run.sh's" \
         "--tmpfs /data mount before running disk-fill." >&2
    exit 1
fi

docker exec "$SIM_CONTAINER" fallocate -l "${fill_kb}K" /data/fill.bin \
    || docker exec "$SIM_CONTAINER" sh -c "dd if=/dev/zero of=/data/fill.bin bs=1024 count=${fill_kb} 2>/dev/null"

used_pct="$(docker exec "$SIM_CONTAINER" sh -c "df -P /data | awk 'NR==2{gsub(/%/,\"\",\$5); print \$5}'")"
echo "disk-fill: armed, /data now ${used_pct}% used"

if [ "$used_pct" -lt 70 ]; then
    echo "disk-fill: FAIL — /data only ${used_pct}% used after fill" >&2
    exit 1
fi
