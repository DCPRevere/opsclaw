#!/usr/bin/env bash
# Supervised port-forwards from the daemon's machine into the sandbox
# cluster, using opsclaw's OWN scoped kubeconfig (the SA has the
# pods/portforward verb and nothing writable):
#
#   localhost:9201 -> logs/coresearch-es-http:9200                     (Elasticsearch, HTTPS)
#   localhost:9202 -> monitoring/prometheus-stack-kube-prom-prometheus:9090  (Prometheus, HTTP)
#
# Each forward restarts on exit (a port-forward drops whenever its backing
# pod restarts). Run in a spare terminal, tmux pane, or a user systemd
# unit; Ctrl-C stops both.
set -euo pipefail

KUBECONFIG_PATH="${1:-$HOME/.opsclaw/sandbox-kubeconfig.yaml}"

forward() {
  local ns=$1 svc=$2 local_port=$3 remote_port=$4
  while true; do
    echo "[$(date +%H:%M:%S)] forwarding localhost:$local_port -> $ns/$svc:$remote_port"
    kubectl --kubeconfig "$KUBECONFIG_PATH" -n "$ns" \
      port-forward "svc/$svc" "$local_port:$remote_port" || true
    echo "[$(date +%H:%M:%S)] forward $svc dropped; retrying in 3s"
    sleep 3
  done
}

trap 'kill 0' EXIT INT TERM
forward logs coresearch-es-http 9201 9200 &
forward monitoring prometheus-stack-kube-prom-prometheus 9202 9090 &
wait
