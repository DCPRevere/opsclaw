#!/usr/bin/env bash
# Generate opsclaw's standalone kubeconfig from the ServiceAccount token
# minted by deploy/sandbox-rbac.yaml. Run with YOUR credentials (the same
# context you applied the RBAC with); the output file authenticates as the
# scoped `opsclaw` ServiceAccount only — no AAD, no interactive login, safe
# for a daemon.
#
#   deploy/gen-opsclaw-kubeconfig.sh [context] [output-path]
#
# Defaults: context example-sandbox,
#           output  ~/.opsclaw/sandbox-kubeconfig.yaml
set -euo pipefail

CONTEXT="${1:-example-sandbox}"
OUT="${2:-$HOME/.opsclaw/sandbox-kubeconfig.yaml}"
NS=opsclaw
SECRET=opsclaw-token

echo "reading ServiceAccount token from $NS/$SECRET (context $CONTEXT)..."
TOKEN=$(kubectl --context "$CONTEXT" get secret "$SECRET" -n "$NS" -o jsonpath='{.data.token}' | base64 -d)
CA=$(kubectl --context "$CONTEXT" get secret "$SECRET" -n "$NS" -o jsonpath='{.data.ca\.crt}')
SERVER=$(kubectl config view --minify --context "$CONTEXT" -o jsonpath='{.clusters[0].cluster.server}')

if [ -z "$TOKEN" ] || [ -z "$CA" ] || [ -z "$SERVER" ]; then
  echo "ERROR: could not read token/ca/server — is deploy/sandbox-rbac.yaml applied?" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
umask 077
cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: sandbox
    cluster:
      server: $SERVER
      certificate-authority-data: $CA
users:
  - name: opsclaw
    user:
      token: $TOKEN
contexts:
  - name: opsclaw-sandbox
    context:
      cluster: sandbox
      user: opsclaw
current-context: opsclaw-sandbox
EOF
chmod 600 "$OUT"

echo "wrote $OUT (mode 600, context opsclaw-sandbox, server $SERVER)"
echo
echo "smoke test (read-only, as the scoped SA):"
echo "  kubectl --kubeconfig $OUT get pods -A --no-headers | head"
echo
echo "hand the PATH to opsclaw's secret store:"
echo "  printf '%s' \"$OUT\" | opsclaw-cli secret set sandbox-kubeconfig"
