# Changelog

Operator-facing changes. Anything that needs manual work at upgrade time
carries a **Deploying** note (AGENTS.md); read those before rolling a
release out.

## Unreleased

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
