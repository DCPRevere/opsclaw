#!/usr/bin/env bash
set -euo pipefail
iptables -D INPUT -p tcp --dport 8080 -j DROP 2>/dev/null || true
