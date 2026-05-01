<div align="center">

<pre>
 ░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░       ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█████████████▓▒░ 
</pre>

</div>

<p align="center">
  <strong>An SRE agent that runs as a daemon.</strong><br>
  Built on the <a href="https://github.com/zeroclaw-labs/zeroclaw">zeroclaw</a> runtime. Rust. Single binary.
</p>

<p align="center">
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-edition%202024-orange?logo=rust" alt="Rust edition 2024" /></a>
  <a href="https://github.com/dcprevere/opsclaw/releases/latest"><img src="https://img.shields.io/badge/opsclaw-v0.6.2-blue" alt="opsclaw v0.6.2" /></a>
</p>

opsclaw is an SRE agent. It connects to servers and Kubernetes clusters over SSH or `kubeconfig`, runs diagnostics, follows runbooks, escalates incidents, and persists state across runs. It runs as a daemon and notifies through configured channels.

It is a fork of [zeroclaw](https://github.com/zeroclaw-labs/zeroclaw), which provides the agent loop, tool dispatch, channels, memory, gateway, and scheduler. SRE-specific tools and conventions are layered on top.

## What it does

On alert or heartbeat:

- selects a diagnostic tool to confirm the signal
- correlates observations into a hypothesis
- acts within configured policy, or escalates with a structured payload

## Quick start

```bash
# Build
cargo build --release --locked

# Set your provider key (interactive — onboard encrypts it at rest)
./target/release/opsclaw onboard

# Add a project, environment, and first target in one flow
./target/release/opsclaw config project add

# Confirm setup
./target/release/opsclaw doctor

# Start the autonomous loop
./target/release/opsclaw daemon
```

Need a binary? `./install.sh` after building, or grab a release.

## Glossary

opsclaw uses a three-level hierarchy you'll see throughout the CLI and config:

- **target** — a concrete machine or cluster opsclaw can act on (`ssh`, `local`, or `kubernetes`).
- **project** — a logical grouping of targets (one app, one service line).
- **environment** — the blast-radius boundary above project (`prod`, `staging`, `default`).

Every target has an **autonomy level** that controls how much opsclaw acts on its own:

| Level | Behaviour |
|---|---|
| `observe` | Read-only. Monitor and report; never act. |
| `suggest` | Propose fixes; wait for human approval. Default for new targets. |
| `act_on_known` | Auto-apply runbook remediations; ask for the rest. |
| `auto` | Act and log everything. For trusted, well-runbooked workloads. |

Escalations go out through `opsclaw_notify` — a structured payload (severity, target, signals, hypothesis, recommendation) routed to whichever channels you configured (Telegram, Slack, PagerDuty, etc).

## How the agent runs

The runtime owns four concurrent subsystems:

- **Heartbeat** — the autonomous loop. Reads tasks from `HEARTBEAT.md`, ticks on an adaptive interval, decides what to run, runs it, and consolidates memory across ticks.
- **Channels** — inbound messaging and outbound notifications.
- **Gateway** — HTTP / WebSocket API for webhooks and the dashboard.
- **Scheduler** — cron-driven jobs.

Workspace files (`AGENTS.md`, `SOUL.md`, `IDENTITY.md`, `USER.md`, `TOOLS.md`, `MEMORY.md`) under `~/.opsclaw/workspace/` persist agent state across restarts. They are injected into the system prompt at the start of each session.

## Tools

opsclaw ships SRE-shaped tools on top of the zeroclaw default set:

- **diagnostic** — `monitor`, `ssh`, `kube`, `systemd`, `docker`, `dns`, `cert`, `firewall`
- **observability** — `prometheus`, `loki`, `elk`, `jaeger`
- **provider/infra** — `pagerduty`, `cloudflare`, `github`, `azure_service_bus`, `rabbitmq`, `postgres`, `posthog`
- **escalation** — `opsclaw_notify`
- **upstream zeroclaw** — `shell`, `file_read`, `file_write`, `memory_recall`, `memory_store`, `web_search`, `web_fetch`

## CLI

```bash
# First-run setup (provider, channels, memory, gateway)
opsclaw onboard

# Composable hierarchy wizards (any of these chains into the next steps)
opsclaw config project add        # project → optional env → optional target
opsclaw config env add            # env under existing project → optional target
opsclaw config target add         # target under existing project + env

opsclaw config project list
opsclaw config env list
opsclaw config target list

# Run things
opsclaw daemon                    # the autonomous loop
opsclaw gateway start             # HTTP/WebSocket API + dashboard
opsclaw agent                     # interactive chat
opsclaw agent -m "why is web-1 slow?"

# Inspect state
opsclaw status                    # daemon + agent status
opsclaw doctor                    # diagnostics
opsclaw scan <target>             # one-off discovery scan
opsclaw memory list               # past incidents and notes
```

## Configuration

opsclaw reads `~/.opsclaw/config.toml`. The file is created and managed by `opsclaw onboard` and the `config` subcommands — most users never edit it by hand.

A minimal hierarchy looks like this:

```toml
# Project: acme
[[projects]]
name = "acme"

[[projects.environments]]
name = "prod"

[[projects.environments.targets]]
name = "web-1"
type = "ssh"
host = "web-1.example.com"
user = "root"
key_secret = "enc2:..."          # encrypted; reference by name in your store
autonomy = "suggest"

[[projects.environments.targets]]
name = "web-2"
type = "ssh"
host = "web-2.example.com"
user = "root"
key_secret = "enc2:..."
autonomy = "suggest"

[[projects.environments]]
name = "staging"

[[projects.environments.targets]]
name = "web-staging"
type = "ssh"
host = "web-staging.example.com"
user = "root"
key_secret = "enc2:..."
autonomy = "act_on_known"

# Project: cluster
[[projects]]
name = "cluster"

[[projects.environments]]
name = "prod"

[[projects.environments.targets]]
name = "k8s-prod"
type = "kubernetes"
kubeconfig = "~/.kube/config"
context = "prod-cluster"
autonomy = "observe"
```

TOML's `[[a.b.c]]` syntax attaches each child to the **most recent** parent that came before it in the file. So the first `[[projects.environments]] name = "prod"` belongs to `acme`; the second `[[projects.environments]] name = "prod"` (further down) belongs to `cluster`. The same env name can repeat across projects without collision.

Secrets (SSH keys, API tokens) are referenced by name; the values live encrypted at rest and are never written to logs.

Override paths and behaviour with environment variables:

| Var | Purpose |
|---|---|
| `OPSCLAW_CONFIG_DIR` | Override config dir (default `~/.opsclaw/`) |
| `OPSCLAW_GATEWAY_HOST` | Gateway bind address (default `127.0.0.1`) |
| `OPSCLAW_GATEWAY_PORT` | Gateway bind port |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` | Provider credentials |
| `RUST_LOG` | Log level (default `info`) |

## Architecture

opsclaw is a Cargo workspace. The SRE agent lives in `crates/opsclaw`; the rest is the upstream zeroclaw runtime plus a few independent toolkits.

| Area | Crates |
|---|---|
| opsclaw SRE agent | `crates/opsclaw` — SSH/k8s/observability tools, hierarchy CLI, daemon hooks, runbooks. |
| zeroclaw runtime | `crates/zeroclaw-*` — runtime, providers, channels, config, memory, gateway, tools, TUI. |
| Independent | `crates/robot-kit`, `crates/aardvark-sys` — robotics/embedded toolkits, unrelated to the SRE agent. |

The `zeroclawlabs` umbrella crate at the workspace root re-exports the upstream crates so dependents can pull them in by a single name.

## Security

opsclaw connects to real infrastructure. Treat it accordingly.

- **Sandboxing** — workspace isolation, path-traversal guards, command allowlists, forbidden paths.
- **Approval gating** — interactive approval for medium/high-risk operations under `suggest` autonomy.
- **Audit log** — every remote command is hash-chained and append-only.
- **Secrets** — referenced by name; values live encrypted at rest, never written to config files or logs.
- **E-stop** — emergency shutdown capability.

See [SECURITY.md](SECURITY.md) for the full policy.

## Build and test

```bash
cargo build                          # debug
cargo build --release                # size-optimized (lto=fat, stripped)
cargo build --profile release-fast   # faster local release builds
cargo test --workspace               # run all tests
```

Optional capabilities (Prometheus, Matrix, WhatsApp, OpenTelemetry, etc.) are gated behind feature flags. Check `Cargo.toml` before assuming a dependency is available.

For tier-1/2/3 production-readiness testing, see [`docs/testing.md`](docs/testing.md).

## Upstream

opsclaw tracks [zeroclaw-labs/zeroclaw](https://github.com/zeroclaw-labs/zeroclaw) as `upstream` for the agent runtime, providers, channels, memory, and gateway. SRE-specific code (SSH/k8s/observability tools, the project/env/target hierarchy, configuration wizards, daemon hooks) lives in `crates/opsclaw` so upstream changes can be merged cleanly.

## Documentation

Full documentation lives under [`docs/`](docs/):

- [`getting-started.md`](docs/getting-started.md) — first install through first scan.
- [`hierarchy.md`](docs/hierarchy.md), [`projects.md`](docs/projects.md), [`environments.md`](docs/environments.md), [`targets.md`](docs/targets.md) — the configuration model.
- [`autonomy.md`](docs/autonomy.md) — what the agent will and won't do at each level.
- [`runbooks.md`](docs/runbooks.md) — codifying remediations the agent can execute.
- [`channels.md`](docs/channels.md) — wiring up notifications.
- [`memory.md`](docs/memory.md) — how the agent remembers.
- [`SECURITY.md`](SECURITY.md) — the threat model and the audit chain.

## License

All rights reserved.
