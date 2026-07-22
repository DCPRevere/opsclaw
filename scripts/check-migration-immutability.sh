#!/usr/bin/env sh
# Applied migrations are immutable (AGENTS.md): sqlx checksums each file and a
# mismatch crash-loops the daemon on boot. Enforce that structurally: every
# migration file that existed at the newest release tag must be byte-identical
# in the working tree. NEW migration files are always fine — only drift in
# frozen ones fails. Called by `just check-migrations` (so `just ci` and the
# release recipe) and by .github/workflows/ci.yml, which fetches full history
# + tags (fetch-depth: 0) so the base ref resolves.
#
# Migration filenames are the repo's own NNNN_name.sql convention (no spaces),
# so plain word-splitting over `git ls-tree` output is safe here.
set -eu
cd "$(dirname "$0")/.."

base="$(git describe --tags --abbrev=0 2>/dev/null || true)"
if [ -z "$base" ]; then
    echo "check-migrations: no release tag yet — nothing is frozen (the first tag freezes them). OK."
    exit 0
fi

status=0
for f in $(git ls-tree -r --name-only "$base" -- migrations); do
    if [ ! -f "$f" ]; then
        echo "check-migrations: DRIFT — $f existed at $base but is missing from the working tree" >&2
        status=1
        continue
    fi
    if ! git cat-file blob "$base:$f" | cmp -s - "$f"; then
        echo "check-migrations: DRIFT — $f differs from its content at $base (write a NEW numbered migration instead)" >&2
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "check-migrations: every migration frozen at $base is byte-identical. OK."
fi
exit "$status"
