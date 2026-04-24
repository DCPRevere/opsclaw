#!/usr/bin/env bash
set -euo pipefail
iptables -D INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || true
