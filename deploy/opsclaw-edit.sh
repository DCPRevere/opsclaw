#!/bin/sh
# One-step config editing for a CONTAINERISED install: show → $EDITOR → apply.
#
# `opsclaw-cli config edit` cannot do this itself when the daemon runs in the
# standard image. The editor has to run where a terminal and an editor exist —
# the host — while the config lives in a docker volume only the container can
# reach. deploy/Dockerfile installs ca-certificates and curl and nothing else,
# and putting vim in a production image to support an interactive workflow is
# the wrong trade. So the editing happens here and only the read and the write
# cross the container boundary.
#
#   ./opsclaw-edit.sh              # edit the running config
#   EDITOR=nano ./opsclaw-edit.sh  # $EDITOR/$VISUAL respected, vi by default
#
# Run it from the directory holding docker-compose.yml and .env, or set
# OPSCLAW_DIR. The safety properties are `config apply`'s, not this script's:
# the daemon parses and runs its OWN Config::validate() before writing, so a
# rejected config is never written and this script cannot brick an install.

set -eu

dir="${OPSCLAW_DIR:-$(dirname "$0")}"
cd "$dir"

if [ ! -f docker-compose.yml ] || [ ! -f .env ]; then
    echo "opsclaw-edit: no docker-compose.yml and .env in $(pwd)" >&2
    echo "              cd to your install directory, or set OPSCLAW_DIR" >&2
    exit 1
fi

dc() {
    # -T everywhere: exec allocates a TTY by default, which mangles a piped
    # stream in both directions (carriage returns on the way out, a swallowed
    # heredoc on the way in).
    docker compose --env-file .env exec -T opsclaw-daemon "$@"
}

work="$(mktemp "${TMPDIR:-/tmp}/opsclaw-config.XXXXXX.toml")"
original="$(mktemp "${TMPDIR:-/tmp}/opsclaw-config-orig.XXXXXX.toml")"
# The work file holds no secret VALUES — config carries env:VAR / store:KEY
# references only — but it is the daemon's whole configuration, so keep it
# off other users' eyes on a shared box.
chmod 600 "$work" "$original"
cleanup() { rm -f "$original"; }
trap cleanup EXIT

# Read FIRST and check it worked before opening an editor: a failed exec would
# otherwise leave an empty file that looks like a config the operator wiped.
if ! dc opsclaw-cli config show > "$work"; then
    echo "opsclaw-edit: could not read the config — is opsclaw-daemon running?" >&2
    rm -f "$work"
    exit 1
fi
if [ ! -s "$work" ]; then
    echo "opsclaw-edit: the daemon returned an empty config; refusing to edit it" >&2
    rm -f "$work"
    exit 1
fi
cp "$work" "$original"

# Through a shell, not as one executable name: $EDITOR and $VISUAL commonly
# carry flags ("emacsclient -c", "code -w", "emacs -nw"), and running the
# whole string as a command fails with "command not found" — naming the
# editor but not the reason. The path is ours, not operator input.
# `set -e` aborts here if the editor exits non-zero, leaving the running
# config untouched, which is the same stance `opsclaw-cli config edit` takes.
sh -c "${VISUAL:-${EDITOR:-vi}} \"\$1\"" sh "$work"

if cmp -s "$work" "$original"; then
    echo "no changes — config left alone"
    rm -f "$work"
    exit 0
fi

# On refusal the daemon has written nothing, so the running config is intact
# and the operator's edit is the only thing worth keeping.
if ! dc opsclaw-cli config apply < "$work"; then
    echo >&2
    echo "opsclaw-edit: REFUSED — the running config is unchanged." >&2
    echo "              Your edit is kept at $work" >&2
    echo "              Fix it and re-apply with:" >&2
    echo "                docker compose --env-file .env exec -T opsclaw-daemon \\" >&2
    echo "                    opsclaw-cli config apply < $work" >&2
    exit 1
fi

rm -f "$work"
# No restart line here: `config apply` prints its own, and it detects whether
# it is running in a container so it names the right mechanism. Two nearly
# identical instructions naming slightly different commands is worse than one.
