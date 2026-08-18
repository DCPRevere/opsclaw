#!/bin/sh
set -eu

cli=$1
daemon=$2
port=$3
test_home=$(mktemp -d "${TMPDIR:-/tmp}/opsclaw-web-smoke.XXXXXX")

# Seed the first operator through the same local CLI operators use. The
# password travels on stdin, never argv.
printf '%s\n' 'web-smoke-password' | env -i \
  PATH="${PATH:-/usr/bin:/bin}" \
  HOME="$test_home" \
  OPSCLAW_HOME="$test_home" \
  "$cli" accounts add web@example.com --name 'Web Operator'

exec env -i \
  PATH="${PATH:-/usr/bin:/bin}" \
  HOME="$test_home" \
  OPSCLAW_HOME="$test_home" \
  OPSCLAW_LISTEN="127.0.0.1:$port" \
  RUST_LOG="opsclaw=warn" \
  "$daemon"
