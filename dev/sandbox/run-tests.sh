#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Generate SSH keypair if not present
if [ ! -f keys/sandbox_ed25519 ]; then
  mkdir -p keys
  ssh-keygen -t ed25519 -f keys/sandbox_ed25519 -N "" -C "opsclaw-sandbox"
  echo "Generated sandbox SSH keypair"
fi

echo "=== Starting sandbox ==="
docker compose up -d --build

echo "Waiting for services to be ready..."
sleep 10

echo ""
echo "=== Test 1: Remote mode — opsclaw scan ==="
docker compose exec -e OPSCLAW_LLM_API_KEY="${OPSCLAW_LLM_API_KEY:-test}" opsclaw-remote \
  opsclaw scan --target sandbox --config /etc/opsclaw/config.toml
echo "Test 1: PASSED"

echo ""
echo "=== Test 2: Sidecar mode — opsclaw scan ==="
docker compose exec -e OPSCLAW_LLM_API_KEY="${OPSCLAW_LLM_API_KEY:-test}" opsclaw-sidecar \
  opsclaw scan --target sandbox-local --config /etc/opsclaw/config.toml
echo "Test 2: PASSED"

echo ""
echo "=== Test 3: Resilience — kill app container and scan ==="
docker compose stop sandbox-app
sleep 2
docker compose exec -e OPSCLAW_LLM_API_KEY="${OPSCLAW_LLM_API_KEY:-test}" opsclaw-remote \
  opsclaw scan --target sandbox --config /etc/opsclaw/config.toml
docker compose start sandbox-app
echo "Test 3: PASSED"

echo ""
echo "=== All tests passed. Tearing down. ==="
docker compose down -v
