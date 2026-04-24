#!/usr/bin/env bash
# Negative scenario: no fault at all. The agent is expected to observe
# the healthy baseline and NOT call opsclaw_notify.
set -euo pipefail
true
