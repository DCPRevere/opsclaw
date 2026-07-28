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

- **Switching the provider needs a RELEASE, not just a config edit.** The
  login page and its scripts are `include_str!`'d into the binary, so a
  running daemon serves whatever shell it was built with. Flipping `[auth]`
  under an older binary leaves operators looking at a password form whose
  every submission is refused by the handler. Ship the binary first, then
  the config.
- **Link operator rows to Hanko subjects BEFORE the flip.** Take each
  operator's user id from the Hanko console and run `opsclaw-cli account link
  <email> --hanko-subject <id>` for every existing operator (`account create
  <email> --hanko-subject <id>` is for operators who have no row yet). An
  identity that Hanko authenticates but no account row claims gets a 401, so a
  flip with an unlinked roster locks everyone out. `account link` works while
  the daemon is still on `local`, which is the point: link the whole roster
  first, then flip.
- **Rollback needs the database, not just the config and binary.** `Config` is
  `deny_unknown_fields`, so a config carrying `[auth]` does not parse on a
  binary that predates it — the daemon refuses to start. Roll the config back
  together with the binary, never separately. Migration 0009 is the harder
  half: sqlx validates applied migrations against the embedded set at boot and
  refuses to start when the database records a migration the binary does not
  have, so an older binary will NOT start against an upgraded database. Take a
  copy of the SQLite file before upgrading; restoring it is what makes a
  rollback possible.
- **Mint a break-glass CLI token first and store it offline.** While password
  sign-in still works, run `opsclaw-cli login --remote <gateway-url>` and
  keep the resulting `~/.opsclaw/cli.toml` token somewhere out of band. Under
  `hanko` password sign-in is refused outright, and an `ops_` token reaches
  every operator route including `opsclaw-cli estop --remote`. It is the only
  way in if Hanko is unreachable or the passkey enrolment is wrong.
- **Offboarding is a step here too.** Deactivating a user at the identity
  provider does not reach this daemon: an issued session cookie stays valid
  until it expires, and CLI tokens never expire. Run `opsclaw-cli account
  revoke-sessions <email>` to bump `token_version` and drop every `ops_`
  token for that operator.

Hanko-side settings (`cors.allow_origins`, `webauthn.relying_party.id` and
`.origins`, `session.audience`, `session.enable_auth_token_header`) each fail
quietly when wrong; `deploy/config.sandbox.example.toml` lists them with the
trap in each. `webauthn.relying_party.id` is a one-way door — passkeys are
bound to it and changing it later orphans every enrolment.
