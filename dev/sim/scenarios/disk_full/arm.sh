#!/usr/bin/env bash
# Disk full: /data is a 200M tmpfs; allocate 195M so df shows ~98%.
set -euo pipefail
rm -f /data/big
fallocate -l 195M /data/big
