# AGENTS.md

## Branches

Do all work on master or using worktrees unless explicitly asked.

## Operational invariants (hard-won in gianna's prod — don't relearn them here)

- **Applied migrations are immutable.** Never edit any existing file under
  `migrations/` — sqlx checksums the whole file and a mismatch crash-loops the
  daemon on boot. Every change is a NEW numbered migration.
- **Seeded scan-job prompts resolve from code constants at fire time.** The
  default per-project scan prompts live as consts in the scheduler and are
  read fresh each tick, not snapshotted into a DB row at seeding — so unlike
  gianna's routine prompts, editing a const DOES propagate to existing
  projects immediately. Treat that propagation as real: a prompt change is a
  behaviour change for every project on the next tick, not just new ones.
- **This checkout can host parallel sessions.** Never `git add -A`; stage
  explicit paths, and re-check `git status`/`git log` before committing or
  merging.
- **Pin agent worktrees.** Spawned worktrees base on origin/master, which can
  trail local master — every agent must verify its HEAD against the intended
  commit before doing anything.
- **Run the repo parity suite before merging repo/scheduler/SQL changes.**
  OpsClaw's store is SQLite (DESIGN.md §7.2), so parity runs unconditionally
  under plain `cargo test` — no throwaway container needed, no env var to set.
  If a repo/scheduler/SQL change doesn't turn this suite red when it should,
  the suite is the bug.
- **Embedded frontend/prompts need a release to show.** The web UI and system
  prompts are `include_str!`'d into the binary; a running daemon reflects
  edits only after the next release. Anything needing manual ops gets a
  **Deploying** note in the CHANGELOG.
- **The Hindsight image is pinned in lockstep with the standard install**
  (`docker-compose.yml`) — never bump it casually; see DESIGN.md §5.
- **Verification beats confidence.** Agents fixing or building things must
  run what they built (live eval, parity suite, the actual test) and report
  real output; "it should work" is not a report.
- **The safety invariant.** No code path may reach a `TargetExecutor` except
  through `policy::execute`. This is checked by construction, not convention
  — if a change adds a new way to invoke a target tool, it goes through
  `policy::execute` or it doesn't ship. See DESIGN.md and
  `docs/plans/IMPLEMENTATION.md` §0.3 ("Safety before brain").
- **Voice.** Agent output (chat replies, escalation payloads, alerts) is
  plain SRE prose: no emoji, no exclamation marks in alerts, no sign-offs.
  State what happened and what's needed, nothing more.

## Committing

- Commits go directly to master with small, focused commits.
- No AI attribution: no mention of Claude/AI authorship, no
  `Co-Authored-By` trailers.
- **Never push to any remote without an explicit user ask.** Landing on local
  master is not authorization to push.
- **Ported gianna code cites its gianna source file in the commit message**
  (e.g. `port: cargo add sqlx repo trait (from gianna src/db/repo.rs)`), not
  in code comments — the code is owned here, not tracking upstream.
- **Two-commit porting rule**: port verbatim (rename-only) in one commit,
  adapt in the next. Keeps regressions attributable — did we break it, or did
  gianna never do it? (`docs/plans/IMPLEMENTATION.md` §0.2)

## Releasing and tagging

See the justfile.

## Documentation

Keep internal and external documentation MINIMAL and CONCISE — huge reams of
docs that nobody reads are worse than none. Before adding a document, prefer
extending an existing one; before extending, prefer deleting something stale.
A doc that has served its purpose (a finished checklist, a shipped plan) gets
rewritten down to what is still true or removed.

### Plans

Plans go in docs/plans.
