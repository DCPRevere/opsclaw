#!/usr/bin/env bash
#
# Tier 1 — tool-level tests.
#
# These are plain unit tests for the opsclaw tools/* modules. HTTP-backed
# tools use wiremock; shell-backed tools use a mocked executor trait. No
# external services are touched.
#
# This is a thin passthrough over cargo test. Exit code is cargo's.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

exec cargo test -p opsclaw --bin opsclaw tools:: "$@"
