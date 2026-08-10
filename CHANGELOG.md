# Changelog

Operator-facing changes. Anything that needs manual work at upgrade time
carries a **Deploying** note (AGENTS.md); read those before rolling a
release out.

## v0.1.1

### The standard docker install actually starts

`v0.1.0` published a working image that no one could start from the
documented instructions. Two independent faults, both found by installing it
the way a stranger would — no checkout, anonymous pull.

**A blank credential counted as a configured one.** `deploy/.env.example`
shipped every optional secret as a bare `NAME=`, and compose forwards them
unconditionally, so the container always received `OPENROUTER_API_KEY` with
an empty value. `apply_env_overlay` tested only `var_os().is_some()`, so that
read as a configured LLM: the daemon left fakes mode, demanded `llm.models`
and a real `http.jwt_secret`, and crash-looped — for a user who had followed
the example file exactly, under a header promising that blank means disabled.
Empty and whitespace-only values are now "not configured", matching the rule
`OPSCLAW_MODELS`, `HINDSIGHT_URL` and `OPSCLAW_LISTEN` already applied inline.
`TELEGRAM_BOT_TOKEN` had the same fault and the same fix. Non-UTF-8 still
counts as set: a key this daemon cannot decode is a real key, badly stored.

**The documented setup order could not be followed.** The compose file said
to `up -d` and then `exec ... onboard`. But the file always sets
`HINDSIGHT_URL`, so the daemon is always live, and live mode refuses to boot
without `http.jwt_secret` — which `onboard` is what generates. On a fresh
volume the daemon therefore crash-loops, and Docker will not `exec` into a
restarting container. Rewritten to onboard FIRST via `docker compose run
--rm`, which starts a one-off container with a different command and writes
`config.toml` onto the same volume.

**The bundled Hindsight's API key was marked optional, and is not.**
`HINDSIGHT_LLM_API_KEY` used `:-` while its three neighbours used `:?`, but
Hindsight raises `LLM API key is required` and crash-loops without one. The
only symptom was an opsclaw `doctor` FAIL on an unreachable memory backend,
with the real cause in a different container's logs. It is now `:?`, so
compose refuses to start with a message naming the variable.

Also: optional credentials in `.env.example` are now commented out rather
than blank, and the Dockerfile's mtime guard covers `static/` — the hanko
merge began `include_str!`ing the whole web shell, so a rebuild Cargo decides
to skip ships an image whose UI is silently a build behind.

**Deploying** — no action for an existing install. An existing `.env` with
blank credentials is now read the way it always looked like it would be. If
`v0.1.0` would not start for you, `v0.1.1` fixes it; nothing else changes.

## v0.1.0

The first published container image: `ghcr.io/dcprevere/opsclaw`, at
`:v0.1.0` and `:latest`, built and pushed by a `v*` tag. Everything below
shipped in it.

### Pluggable login provider (`[auth]`)

Login is now a config choice (DESIGN §7 decision 16). `auth.provider =
"local"` is the default and keeps today's argon2 password sign-in.
`auth.provider = "hanko"` replaces the password form with a Hanko passkey
widget; the daemon verifies each sign-in against the Hanko API server-side
and then mints its own session cookie exactly as before. `Authed`, the `ops_`
CLI bearer, SSE stream tickets and `token_version` revocation are unchanged
under both providers, and a Hanko token is never accepted on an ordinary
request. Operator rows link to a Hanko identity by user id; there is no
auto-provisioning.

Also: `opsclaw-cli account create --hanko-subject <id>`, `opsclaw-cli account
revoke-sessions <email>`, `GET /api/auth/config`, `POST
/api/auth/hanko/exchange`, and migration `0009_account_auth_provider.sql`.

**Deploying** — only if you are switching a deployment to `hanko`; a
deployment staying on `local` needs nothing.

1. **Mint a break-glass CLI token and store it offline.** Do this FIRST,
   while password sign-in still works: `opsclaw-cli login --remote
   <gateway-url>`, then keep the resulting `~/.opsclaw/cli.toml` token out of
   band. Under `hanko` password sign-in is refused outright, and
   `opsclaw-cli login` is a browser hand-off that needs a working web sign-in
   to approve — so this token cannot be minted once the flip is under way. An
   `ops_` token reaches every operator route including `opsclaw-cli estop
   --remote`, and it is the only way in if Hanko is unreachable or the passkey
   enrolment is wrong. Rotate it once the flip has succeeded.
2. **Take a copy of the SQLite file.** Migration 0009 is what makes rollback
   hard: sqlx validates applied migrations against the embedded set at boot and
   refuses to start when the database records one the binary does not have, so
   an older binary will NOT start against an upgraded database. `Config` is
   also `deny_unknown_fields`, so a config carrying `[auth]` does not parse on
   a binary that predates it. Roll config and binary back together, and keep
   the pre-upgrade database to roll back to.
3. **Link operator rows to Hanko subjects, before the flip.** Take each
   operator's user id from the Hanko console and run `opsclaw-cli account link
   <email> --hanko-subject <id>` for every existing operator (`account create
   <email> --hanko-subject <id>` is for operators who have no row yet). An
   identity that Hanko authenticates but no account row claims is refused, so a
   flip with an unlinked roster locks everyone out. Linking works while the
   daemon is still on `local` and KEEPS each account's password, so the roster
   can be linked days ahead with no loss of access. `opsclaw-cli doctor` and
   `opsclaw-cli account list` both report who is still unlinked — check one of
   them before flipping.

   `--drop-password` clears the password at link time. Do not use it before the
   flip: the hanko route is refused while the provider is still `local`, so
   those operators could sign in by neither method until the flip completed.
   Under `hanko` a surviving password hash is unreachable anyway, because
   `/api/login` is gated on the handler.
4. **Switch the provider — binary first, then config.** The login page and its
   scripts are `include_str!`'d into the binary, so a running daemon serves
   whatever shell it was built with. Flipping `[auth]` under an older binary
   leaves operators looking at a password form whose every submission is
   refused.
5. **End password-derived sessions.** Changing the provider does not invalidate
   sessions that already exist: a cookie minted before the flip stays valid for
   up to seven days and keeps sliding. Run `opsclaw-cli account revoke-sessions
   <email>` for each operator once the flip has succeeded.

Recovery, if the flip goes wrong: `opsclaw-cli account set-password <email>`
puts a usable password back, so rolling `auth.provider` to `local` restores
access without a database restore.

Offboarding, afterwards: deactivating a user at the identity provider does not
reach this daemon — an issued session cookie stays valid until it expires and
CLI tokens never expire. `opsclaw-cli account revoke-sessions <email>` is the
step that actually ends their access.

Hanko-side settings (`cors.allow_origins`, `webauthn.relying_party.id` and
`.origins`, `session.audience`, `session.enable_auth_token_header`) each fail
quietly when wrong; `deploy/config.sandbox.example.toml` lists them with the
trap in each. `webauthn.relying_party.id` is a one-way door — passkeys are
bound to it and changing it later orphans every enrolment.
