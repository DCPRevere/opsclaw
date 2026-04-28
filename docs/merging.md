# Merging from upstream zeroclaw

OpsClaw is a fork of [zeroclaw-labs/zeroclaw](https://github.com/zeroclaw-labs/zeroclaw). Periodically you will want to pull upstream's bug fixes, new providers, channel implementations, and runtime improvements into the OpsClaw tree.

OpsClaw deliberately edits upstream files (branding, env-var names, paths, the `HOST`/`PORT` gateway-bind fix, etc.) rather than working around them. That means every merge has real conflicts. This document is the playbook.

## Setup

The `upstream` remote should already be configured. If not:

```sh
git remote add upstream https://github.com/zeroclaw-labs/zeroclaw
git fetch upstream
```

## Conflict resolution policy

These rules cover the vast majority of conflicts. Apply them mechanically; only deviate when a file genuinely needs hand-merging.

1. **Branding strings — always keep ours.**
   - `ZeroClaw` → `OpsClaw` (proper-case product name).
   - 🦀 → 📟 (literal and `\u{1f980}` / `\u{1F980}` escapes).
   - `~/.zeroclaw` → `~/.opsclaw` (path defaults).
   - `zeroclaw <subcommand>` → `opsclaw <subcommand>` in printed CLI examples.
   - `ZEROCLAW_<NAME>` → `OPSCLAW_<NAME>` in env-var names.

2. **New code from upstream — always take theirs**, then re-apply OpsClaw branding to anything they printed, named, or pathed using the rules above. If upstream introduces a new `ZEROCLAW_FOO` env var, rename it to `OPSCLAW_FOO`.

3. **Architectural rewrites — always take theirs.** When upstream replaces a whole subsystem (e.g. the onboard orchestrator rewrite, the Fluent i18n pipeline, a clean-room channel rewrite), do not try to keep our diffs against the old code — they're now against a deleted file. Take the new architecture wholesale and re-apply branding on top.

4. **`HOST` / `PORT` env-var fallbacks in `crates/zeroclaw-config/src/schema.rs`** — keep our deletion. zsh exports `$HOST=<hostname>` by default, which makes the upstream gateway try to bind a hostname as an IP and fail. `OPSCLAW_GATEWAY_HOST` / `OPSCLAW_GATEWAY_PORT` are the only env overrides we honour.

5. **Files we own outright — keep ours.** `README.md`, `CONTRIBUTING.md`, `CLAUDE.md`, `docs/merging.md`, the `.github/pull_request_template.md`, anything under `crates/opsclaw/`. Upstream changes to these are usually regressions for us.

6. **Files we previously deleted — take upstream's.** When `DU` shows in `git status`, upstream re-added or modified a file we'd dropped. Almost always take theirs (e.g. `AGENTS.md`).

7. **Files upstream deleted — take their deletion.** When `UD` shows, follow them. Our changes were against a file that no longer exists; the new architecture is where the equivalent lives now.

8. **Genuine functional conflict** (both sides changed the same logic differently): pause, read, hand-merge.

## The dangerous sed pattern

The `s/\.zeroclaw/.opsclaw/g` global replace **also matches Rust struct-field accesses and struct-update spreads**. It will silently corrupt:

- `options.zeroclaw_dir` → `options.opsclaw_dir` — but the field is still named `zeroclaw_dir`. Compile error.
- `..zeroclaw_config::schema::Config::default()` (struct-update syntax) → `..opsclaw_config::...` — but `opsclaw_config` is not a real crate. Compile error.
- `permissions.zeroclaw_permissions` — same field-access issue.

After any global path-rebrand sed, run this revert pass:

```sh
find crates -name "*.rs" -exec sed -i \
  -e 's/opsclaw_config::/zeroclaw_config::/g' \
  -e 's/opsclaw_runtime::/zeroclaw_runtime::/g' \
  -e 's/opsclaw_providers::/zeroclaw_providers::/g' \
  -e 's/opsclaw_memory::/zeroclaw_memory::/g' \
  -e 's/opsclaw_channels::/zeroclaw_channels::/g' \
  -e 's/opsclaw_tools::/zeroclaw_tools::/g' \
  -e 's/opsclaw_gateway::/zeroclaw_gateway::/g' \
  -e 's/opsclaw_api::/zeroclaw_api::/g' \
  -e 's/opsclaw_macros::/zeroclaw_macros::/g' \
  -e 's/opsclaw_plugins::/zeroclaw_plugins::/g' \
  -e 's/opsclaw_hardware::/zeroclaw_hardware::/g' \
  -e 's/opsclaw_infra::/zeroclaw_infra::/g' \
  -e 's/opsclaw_tool_call_parser::/zeroclaw_tool_call_parser::/g' \
  -e 's/opsclaw_tui::/zeroclaw_tui::/g' \
  -e 's/\.opsclaw_dir/.zeroclaw_dir/g' \
  -e 's/\.opsclaw_permissions/.zeroclaw_permissions/g' \
  {} +
```

The opsclaw-owned identifiers (`create_opsclaw_tools`, `opsclaw_config_path`, `resolve_opsclaw_dir`) live in `crates/opsclaw/` and should stay opsclaw. The pattern above scopes only the dangerous Rust-path collisions, not those.

## Procedure

```sh
# 1. Land any in-flight work first. Working tree should be clean.
git status

# 2. Fetch upstream.
git fetch upstream

# 3. Survey what is coming. Look for architectural shifts; budget extra
#    time if you see things like "scorched-earth delete", "clean-slate",
#    "clean-room rewrite", "replace X with Y".
git log --oneline HEAD..upstream/master | head -40

# 4. Count conflict-prone files (both sides changed since the merge base).
MB=$(git merge-base HEAD upstream/master)
comm -12 \
  <(git diff --name-only "$MB" HEAD | sort) \
  <(git diff --name-only "$MB" upstream/master | sort) | wc -l

# 5. Merge on a branch (master stays clean if you abort).
git checkout -b merge-upstream-$(date +%Y-%m)
git merge upstream/master --no-edit
```

Resolve conflicts under the policy above. After every batch:

```sh
# Sanity-check no markers left.
git diff --check

# Make sure no UU / DU / UD remain.
git diff --diff-filter=U --name-only

# Build often. Errors get more confusing the deeper you go.
cargo build --workspace
```

When the workspace builds:

```sh
# Optional: re-run any global rebrand seds upstream's new code needs.
# Then run the dangerous-pattern revert pass above.

# Smoke-test the things branding leakage would show in.
cargo build --release -p opsclaw
echo "" | timeout 4 ./target/release/opsclaw onboard 2>&1 | head -25
timeout 2 ./target/release/opsclaw gateway start 2>&1 | head -10

# If those look clean, commit.
git add -A
git commit  # write a commit message describing the merge — see template below

# Fast-forward master.
git checkout master
git merge --ff-only merge-upstream-$(date +%Y-%m)
git branch -d merge-upstream-$(date +%Y-%m)
```

## Commit message template

Merge commits are the audit trail for "what did we adopt, what did we keep, what did we hand-merge". Include:

- **Architectural shifts taken from upstream** — name each one, link the upstream PR if you can. These are the changes future-you will need to know about when grepping for "where did `run_*_wizard` go?".
- **Smaller adopted changes** — signature changes, async/sync flips, renamed APIs, anything that broke the build before you fixed it.
- **Files we kept ours on** — README, CONTRIBUTING, branding, the `HOST`/`PORT` strip.
- **Files we took theirs on** — modify/delete or delete/modify resolutions, Cargo.lock regens.
- **Build status and smoke-test results** — `cargo build --workspace` clean, `opsclaw onboard` renders the new flow, `opsclaw gateway start` binds correctly.

See commit `d0fc2d36 merge: pull upstream zeroclaw master (45 commits)` for a worked example.

## When to abort

Abort if any of these are true:

- The conflict-prone-file count is much higher than your bandwidth allows for one session.
- You hit an architectural rewrite you don't have time to understand properly. Better to revisit in a dedicated session than to half-merge it.
- The build refuses to come up clean after a few iterations and you can't see why.

```sh
git merge --abort
```

The merge branch is independent of master, so aborting and discarding it costs nothing.
