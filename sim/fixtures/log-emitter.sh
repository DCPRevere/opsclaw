#!/usr/bin/env bash
# sim/fixtures/log-emitter.sh — idle heartbeat logger by default (one line
# per 10s to /var/log/opsclaw-sim/app.log, a NLog/ECS-style stand-in for
# remundo's Filebeat-shipped logs, REMUNDO.md). log-flood cranks the rate via
# /run/opsclaw-sim/log-rate-hz; logfile-growth raises line SIZE via
# /run/opsclaw-sim/log-line-bytes instead of rate, to exercise file-size
# growth distinctly from noisy-but-small log volume (brief §9: these are two
# separate known-missed fault classes, kept as two separate control knobs).
set -euo pipefail

RATE_CTL=/run/opsclaw-sim/log-rate-hz
SIZE_CTL=/run/opsclaw-sim/log-line-bytes
APP_LOG=/var/log/opsclaw-sim/app.log

touch "$APP_LOG"
echo "log-emitter: starting pid $$"

# Idle tick counter: emits a heartbeat line only once every IDLE_TICKS
# iterations of a 1s poll loop, so the control files are checked every
# second (armed scenarios take effect within ~1s) while the *default*,
# unarmed cadence stays one line per 10s (avoids the emitter itself being a
# noise source under the silent-baseline scenario).
IDLE_TICKS=10
idle_counter=0

while true; do
    rate_hz=0
    [ -f "$RATE_CTL" ] && rate_hz=$(cat "$RATE_CTL" 2>/dev/null || echo 0)
    [ -n "$rate_hz" ] && [ "$rate_hz" -gt 0 ] 2>/dev/null || rate_hz=0

    line_bytes=80
    [ -f "$SIZE_CTL" ] && line_bytes=$(cat "$SIZE_CTL" 2>/dev/null || echo 80)
    [ -n "$line_bytes" ] && [ "$line_bytes" -gt 0 ] 2>/dev/null || line_bytes=80

    if [ "$rate_hz" -gt 0 ]; then
        payload=$(head -c "$line_bytes" /dev/zero | tr '\0' 'x')
        ts=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        for _ in $(seq 1 "$rate_hz"); do
            echo "${ts} INFO fake-app payload=${payload}" >>"$APP_LOG"
        done
        idle_counter=0
        sleep_interval=$(awk -v r="$rate_hz" 'BEGIN { print 1/r }' 2>/dev/null || echo 1)
        sleep "$sleep_interval" 2>/dev/null || sleep 1
    else
        idle_counter=$((idle_counter + 1))
        if [ "$idle_counter" -ge "$IDLE_TICKS" ]; then
            ts=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
            echo "${ts} INFO fake-app heartbeat" >>"$APP_LOG"
            idle_counter=0
        fi
        sleep 1
    fi
done
