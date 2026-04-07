# Getting started

OpsClaw is an autonomous SRE agent that monitors, diagnoses, and fixes production systems. It ships as a single Rust binary built on the ZeroClaw core library.

## Installation

Build from source (requires Rust 1.87+):

```bash
cargo build --release --locked
# Binary is at target/release/opsclaw
```

Or use the containerised dev environment:

```bash
./dev/cli.sh up      # start environment
./dev/cli.sh build   # build the agent
```

## First run

The setup wizard walks you through initial configuration:

```bash
opsclaw setup
```

Or configure manually:

```bash
opsclaw onboard --provider openrouter --api-key YOUR_KEY
```

This creates `~/.opsclaw/opsclaw.toml` with your provider and model settings.

## Add a target

Targets are the systems OpsClaw monitors. Supported types are `ssh`, `local`, and `kubernetes`.

Store the SSH key for your target in the encrypted secret store:

```bash
opsclaw secret set prod-web-1-key
```

Then add the target to `~/.opsclaw/opsclaw.toml`:

```toml
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
user = "opsclaw"
key_secret = "prod-web-1-key"
autonomy = "suggest"
```

Autonomy levels control how much the agent acts on its own:

- `observe` — monitor and report only
- `suggest` — propose fixes, require approval
- `act_on_known` — auto-apply runbook remediations, ask for unknowns
- `auto` — fully autonomous

## Discovery scan

Run a scan to map the target's processes, containers, services, and disk:

```bash
opsclaw scan prod-web-1
```

Results are saved to `~/.opsclaw/snapshots/prod-web-1.json` and used as context for future diagnoses.

## Start the daemon

The daemon runs the full monitoring loop, gateway, channel listeners, and cron scheduler:

```bash
opsclaw daemon
```

To install it as a system service:

```bash
opsclaw service systemd install
opsclaw service systemd start
```

## Configure alerts

Add a channel to receive notifications. Telegram example:

```toml
[[channels]]
type = "telegram"
name = "ops-alerts"
bot_token = "${TELEGRAM_BOT_TOKEN}"
chat_id = "123456789"
```

Run the channel doctor to verify connectivity:

```bash
opsclaw channel doctor ops-alerts
```

## Scheduled tasks

Add a cron job to run a health check each morning:

```bash
opsclaw cron add --expression "0 9 * * 1-5" --prompt "Check system health and summarise"
```

List scheduled jobs:

```bash
opsclaw cron list
```

## Context files

Each target has a markdown context file at `~/.opsclaw/context/<name>.md`. Add notes about the system — deployment procedures, known quirks, escalation contacts — so the agent can use them during diagnosis:

```bash
opsclaw context edit prod-web-1
```

## Interactive agent

For ad-hoc queries, start a chat session:

```bash
opsclaw agent
```

Or pass a single message:

```bash
opsclaw agent -m "Why is prod-web-1 running slow?"
```

## Gateway API

The gateway exposes an HTTP and WebSocket API for webhooks and the web dashboard:

```bash
opsclaw gateway start
```

Default address is `http://localhost:3000`. Configure in `opsclaw.toml`:

```toml
[gateway]
port = 3000
host = "127.0.0.1"
```

## Diagnostics

Check your own setup:

```bash
opsclaw doctor
```

Review past incidents:

```bash
opsclaw incidents
```

Check system status:

```bash
opsclaw status
```

## Configuration reference

Key environment variables:

| Variable | Purpose |
|---|---|
| `OPSCLAW_CONFIG_DIR` | Override config directory (default `~/.opsclaw`) |
| `OPSCLAW_PROVIDER` | Default LLM provider |
| `OPSCLAW_MODEL` | Default model |
| `OPENROUTER_API_KEY` | OpenRouter API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `RUST_LOG` | Log level (default `info`) |

See `examples/config.example.toml` for a full annotated configuration file.
