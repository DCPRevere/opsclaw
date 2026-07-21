#!/usr/bin/env bash
# silent-baseline — no fault. The target is left exactly as the entrypoint
# leaves it: sshd up, fake-worker/fake-web/log-emitter idling. This is the
# control: the daemon must stay silent against a healthy target (brief §9).
# Idempotent/no-op by construction.
set -euo pipefail
echo "silent-baseline: nothing to arm (healthy target)"
