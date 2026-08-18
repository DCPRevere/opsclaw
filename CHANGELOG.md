# Changelog

Operator-facing changes. Anything that needs manual work at upgrade time
carries a **Deploying** note (AGENTS.md); read those before rolling a
release out.

## v0.3.0

### Team chat follows operational context

Chat now has a global `Operations` conversation and one team-visible
conversation per configured project environment. Every operator can read and
continue the same durable history. Environment selection constrains both the
agent's replay context and its target allow-list; `Operations` cannot invoke
target tools. Live events carry conversation and turn identities so activity
in another room cannot complete or contaminate the current send. Local and
remote CLI chat/history accept `--conversation project::environment` and
default to `operations`.

Existing chat history migrates into `Operations`. Environment turns exclude
scans in the same environment while unrelated environments can continue.
Incident and approval cards follow their target's environment conversation.

**Deploying** — migration `0011_chat_conversations.sql` is applied
automatically. The conversation picker is embedded in the binary, so deploy
the new binary/image before expecting it in the web UI.

### Agent turns and daemon health are failure-safe

Web and remote-CLI chat submissions now carry optional idempotency keys, and
the web client supplies one for every send. Claims and their terminal results
are durable in SQLite: a retry after restart returns the original reply, while
an in-progress or failed turn is never replayed automatically after it may
have acted. A disconnected client no longer cancels an agent turn after a tool
may have acted: turns are shutdown-tracked through their transcript and
idempotency writes. Broad webhook work remains exclusive, while environment
chat and scheduled scans use environment and exact-target conflict domains.
Status lists active and queued turns with their conflict domain and age.

Readiness now probes SQLite; `?deep=1` also probes Hindsight, and the standard
Docker and Kubernetes readiness checks use the deep form. Authentication rate
limits no longer reset at calendar boundaries. OpenRouter failures wrapped in
HTTP 200 retain their embedded retry classification instead of collapsing to
an opaque missing-choices error.

Production logs support `OPSCLAW_LOG_FORMAT=json`, with request-span fields
and the existing credential scrubber preserved; panics are routed through the
same tracing stream. CI now includes browser smoke tests and a weekly RustSec
advisory scan; scheduled advisory failures open or update one GitHub issue.

**Deploying** — migration `0010_chat_requests.sql` is applied automatically.
This also changes the embedded web client and container health checks, so
deploy the new binary/image before expecting durable idempotent sends, live
turn status, or deep readiness. Set `OPSCLAW_LOG_FORMAT=json` only when
structured logs are wanted; human-readable output remains the default.

### Target boundaries are enforced end to end

Seeded scans now persist their exact target and receive only that target and
its resources in tool context. Existing seeded rows are bound automatically
at startup. Tool/target compatibility is checked both at tool resolution and
again before policy classification, and policy classifies the canonical line
the selected executor will actually run.

Kubernetes targets now declare a required context and an explicit namespace
or cluster scope. Namespace targets reject other namespaces and cluster-wide
flags in both the structured tool and executor. The standard image includes a
checksum-verified kubectl client.

**Deploying** — replace a Kubernetes target's old `address = "<context>"`
with an explicit block. Use one of:

```toml
[project.env.target.kubernetes]
context = "my-context"
namespace = "dev"
```

```toml
[project.env.target.kubernetes]
context = "my-context"
cluster_scoped = true
```

This release changes the embedded scan prompt, so running daemons need the new
binary/image before the target isolation behavior is active.

### Spend, scheduler retirement, and the CLI are operable

`opsclaw-cli usage` and daemon status now show today's OpsClaw spend,
Hindsight spend, the configured cap, and remaining headroom. The standard
OpenRouter-backed Hindsight install is included in enforcement; an external
Hindsight whose spend cannot be measured fails closed before model-backed
memory or agent work instead of presenting a false cap.

Retiring a seeded scan now deletes its job and failure history. Moving a
target between environments therefore cannot leave an old disabled row to be
revived later. Operators can also permanently remove jobs with `jobs remove`.

The CLI now has shell completions (including configured `project::env::target`
paths), consistent plural nouns and `add`/`remove` verbs, visible execution
modes in short help, incident acknowledge/resolve, invite management, durable
chat history, and a real `runbooks run --dry-run`. The old `dry-run-log` name
remains as an alias for the accurately named `blocked-actions` report.

The standard container refuses `local` targets because they inspect the
container rather than its host. Put SSH or Kubernetes credentials in
`./creds`; a one-shot compose service now copies them into a private volume
with uid 10001 and safe file modes before the daemon starts.

**Deploying** — before upgrading a container install, replace every `local`
target with an SSH target for the host. Create `./creds`, copy each target
credential into it, and update credential references to
`/home/opsclaw/creds/<name>`. OpenRouter-backed installs need no new billing
variables: the compose file now passes the existing `HINDSIGHT_LLM_BASE_URL`
and `HINDSIGHT_LLM_API_KEY` into the daemon. Other Hindsight providers need an
equivalent metering integration before live LLM work will resume.

### Destructive commands now have brakes

`config rm`, `secret rm`, `memory forget` and `account revoke-sessions` all
destroyed without asking, without previewing and without a `--yes` to make
the intent explicit. `config rm <project>` dropped every environment, target
and resource beneath it in one word. `memory forget` takes FREE TEXT and
deletes every fact it matches, so the blast radius was not even knowable from
the command line.

Each now prints exactly what it will destroy and asks. `config rm` enumerates
the whole subtree rather than counting it — "removes 4 things" does not let
you notice that one of the four is the production cluster — and `memory
forget` prints the CONTENT of every matching fact, not its opaque id.

The third rule is the one that is easy to get wrong: with **no terminal**,
these REFUSE rather than guess. Reading EOF as "yes" destroys data nobody
confirmed; reading it as "no" turns a piped command into a silent no-op that
exits 0 while the operator believes it worked. This is not a corner case —
`docker compose exec -T`, the documented way to reach this CLI, never has a
TTY. Pass `--yes` there.

### The approval queue is reachable from the CLI

`ApprovalRepo::list_pending()` and `GET /api/approvals` have always existed;
no CLI command did. So `opsclaw-cli approve <id>` needed a UUID that nothing
local would print — and `approve`/`deny` were remote-only, requiring a
gateway session, which requires `login`, which is a browser hand-off. On a
host whose web UI is not reachable yet, every route to the queue was closed:
you could watch the agent say "queued for human approval" and have no way to
see the request, let alone answer it.

`approvals list|show|approve|deny` are LOCAL, against the same SQLite file the
daemon uses. Concurrent decisions are safe because `ApprovalRepo::decide` is
an atomic compare-and-set on a pending row — a decision here and one through
the gateway cannot both land. Approving executes the stored command verbatim,
so it needs the daemon's own wiring, exactly as `scan` does.

Who decided is resolved, never invented: `--as <email>`, or the sole operator
account when there is exactly one. With several accounts and no `--as` it
refuses, because `decided_by` lands in an append-only chain and a guess there
forges an attribution.

`approve`/`deny` remain as top-level remote-only aliases; nothing that worked
before changes.

### The audit chain can be read, not just verified

`AuditRepo::range`'s own doc says it exists for "`audit verify` and
inspection". Only verify was ever built, so an operator could prove the log
was untampered and had no way to see what was in it — the append-only record
of every action the agent took was unavailable for the question it exists to
answer. `audit list` (tail by default, `--from` to page) and `audit show
<seq>` read it.

### `tokens list|revoke`

`TokenRepo` and `/api/cli-tokens` existed with no CLI behind them, while this
changelog told operators that `ops_` tokens never expire and that revoking
them is what actually ends someone's access. The documented offboarding step
had no command outside the web UI.

### Also

`config list` shows every project, environment and target with autonomy and
expected-state RESOLVED through the inheritance chain, and takes repeatable
`project[::env[::target]]` filters. Config writes now name the restart command
for the packaging they are running under. `deploy/opsclaw-edit.sh` gives a
containerised install a one-step `show → $EDITOR → apply`.

**Deploying** — no action. Existing configs and databases are read exactly as
before. The one behaviour change to know about is the confirmation prompts: if
you script `config rm`, `secret rm`, `memory forget` or `account
revoke-sessions`, add `--yes` or they will refuse.

## v0.2.0

### The config CLI can now edit, not only append

`opsclaw-cli config` offered `project add`, `resource add` and `validate`.
There was no way to add an environment to an existing project, move a target
between environments, or remove anything — so restructuring meant hand-editing
`config.toml`, and in a container that meant copying the file out of a docker
volume and back. Four commands, all LOCAL (no gateway session, no browser, so
they work over `docker compose exec` on a host with no web access yet):

- `config show` — the file byte-for-byte. Safe to pipe or paste: config holds
  secret REFERENCES (`env:VAR` / `store:KEY`), never values.
- `config apply [--file F]` — replace it from stdin or a file.
- `config edit` — `$EDITOR` round-trip.
- `config rm <project[::env[::target]]>` — remove one thing.

Every write takes the same two gates the gateway's `POST /api/config` takes,
in the same order: parse, then the SAME `Config::validate()` the daemon boots
with, and only then the atomic write with a `.bak`. **A refused config is
never written.** That ordering is the reason these exist rather than a
documented `$EDITOR` recipe — live mode refuses to boot on an invalid config
and Docker will not `exec` into a restarting container, so an unvalidated save
is an install you cannot get back into.

`show`/`apply` round-trip verbatim, so comments and formatting survive.
`rm` re-serializes and cannot preserve comments — the same trade-off the
structured `PUT /api/config/*` routes already make; it says so when it runs.
`rm` on a path that matches nothing is an error listing what does exist:
"removed nothing, exit 0" is how an operator concludes a target is gone while
it is still being scanned.

`config edit` refuses with a pointer to `show`/`apply` when no `$EDITOR` is
set, rather than guessing at `vi`. The runtime image installs only
`ca-certificates` and `curl`, so inside the standard container there is no
editor at all, and a fallback would fail with `No such file or directory` —
naming neither the cause nor the way round it.

### `doctor` checked the operator roster it could not see

`check_db` and `check_account_linkage` ran only when `daemon.db_path` was set
explicitly. Everything else — `boot::daemon_state`, the CLI's own db-path
resolution, and `onboard`'s account wizard — falls back to
`<home>/opsclaw.sqlite3` when config declares nothing, which is the DEFAULT
install. So on a standard setup `onboard` wrote an operator account and then
its own chained `doctor` reported `[OK] operator linkage: no daemon.db_path
configured — no roster to check`, seconds later, about that exact file.

The consequence is worse than a cosmetic gap: this changelog tells operators
to use `doctor` to find unlinked accounts before flipping `auth.provider` to
`hanko`, and warns that flipping with an unlinked roster locks everyone out.
For any deployment that never set `db_path`, that check was inspecting
nothing and passing. Doctor now resolves the same path the daemon will open.
It is still gated on the file EXISTING, because `check_db` connects and
connecting creates — a read-only diagnostic must not create the daemon's
database as a side effect of being run.

### Onboarding no longer asks for what it already knows

**`--hindsight-url` was accepted and ignored.** The flag reached only the
`--yes` path; interactively the prompt hardcoded no default. The onboarding
command in `deploy/docker-compose.yml` passes it, so operators following the
documented install answered a question the flag was supposed to have
answered — and pressing enter wrote "memory: not configured" while the
compose file's own `HINDSIGHT_URL` turned memory on at runtime, leaving
config and behaviour disagreeing. Flags now feed both paths.

**Blank meant "fake it", not "use the obvious value".** Where a flag, the
existing config, or the environment the daemon runs in already answers a
question, that answer is now the prompt's default and enter takes it;
`none` declines it. The skip token is spelled out in the prompt, because the
meaning of a blank answer flips and an unannounced flip would configure
things for operators who were deliberately skipping. Where nothing is
discoverable, blank still skips exactly as before. Detection uses
`Config::env_configured`, the same rule the env overlay applies, so a blank
`OPENROUTER_API_KEY` from `.env.example` is not mistaken for a configured one.

**Model ids are checked against OpenRouter.** A typo was accepted by every
layer: `validate()` only checks the list is non-empty, `doctor` checks the
KEY resolves rather than the MODEL existing, so the first symptom was a
failed reasoning call mid-incident. Unknown ids now produce a warning at
onboard time. Advisory only — an unreachable catalogue, a proxy, or a model
newer than the catalogue must never block an install.

### An environment can be created with no targets

The wizard's target loop ran once unconditionally, so finishing it REQUIRED
inventing a target. The only kind needing no credential is `local`, which
under the docker install resolves to the CONTAINER rather than the host it
appears to name — so the natural way to get through the wizard produced a
target whose readings look real and describe the wrong machine. `validate()`
has always accepted an empty environment; only the prompt did not.

### Containerised targets need their credentials mounted

A credential path in config is opened by the daemon, so it resolves inside
the container — a host path like `~/.kube/config` is simply not there, and a
target configured with one fails at first use rather than at `doctor`.
Nothing said so. `deploy/docker-compose.yml` now documents the mount, and the
uid trap behind it: the container runs as uid 10001, ssh refuses a
group-readable private key, so a mounted key needs its own copy owned by that
uid rather than a relaxed mode.

**Deploying** — no action. Existing configs are read exactly as before; every
change here is to what `onboard` and `doctor` do, not to what they have
written. If `doctor` now reports unlinked operator accounts on a deployment
where it previously said "no roster to check", that finding was always true
and is only now visible.

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
