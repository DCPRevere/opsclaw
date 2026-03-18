# OpsClaw CLI Reference

Complete command reference for the `opsclaw` binary.

## Table of Contents

1. [Agent](#agent)
2. [Onboarding](#onboarding)
3. [Status & Diagnostics](#status--diagnostics)
4. [Memory](#memory)
5. [Cron](#cron)
6. [Providers & Models](#providers--models)
7. [Gateway & Daemon](#gateway--daemon)
8. [Service Management](#service-management)
9. [Channels](#channels)
10. [Security & Emergency Stop](#security--emergency-stop)
11. [Hardware Peripherals](#hardware-peripherals)
12. [Skills](#skills)
13. [Shell Completions](#shell-completions)

---

## Agent

Interactive chat or single-message mode.

```bash
opsclaw agent                                          # Interactive REPL
opsclaw agent -m "Summarize today's logs"              # Single message
opsclaw agent -p anthropic --model claude-sonnet-4-6   # Override provider/model
opsclaw agent -t 0.3                                   # Set temperature
opsclaw agent --peripheral nucleo-f401re:/dev/ttyACM0  # Attach hardware
```

**Key flags:**
- `-m <message>` — single message mode (no REPL)
- `-p <provider>` — override provider (openrouter, anthropic, openai, ollama)
- `--model <model>` — override model
- `-t <float>` — temperature (0.0–2.0)
- `--peripheral <name>:<port>` — attach hardware peripheral

The agent has access to 30+ tools gated by security policy: shell, file_read, file_write, file_edit, glob_search, content_search, memory_store, memory_recall, memory_forget, browser, http_request, web_fetch, web_search, cron, delegate, git, and more. Max tool iterations defaults to 10.

---

## Onboarding

First-time setup or reconfiguration.

```bash
opsclaw onboard                                 # Quick mode (default: openrouter)
opsclaw onboard --provider anthropic            # Quick mode with specific provider
opsclaw onboard                                 # Guided wizard (default)
opsclaw onboard --memory sqlite                 # Set memory backend
opsclaw onboard --force                         # Overwrite existing config
opsclaw onboard --channels-only                 # Repair channels only
```

**Key flags:**
- `--provider <name>` — openrouter (default), anthropic, openai, ollama
- `--model <model>` — default model
- `--memory <backend>` — sqlite, markdown, lucid, none
- `--force` — overwrite existing config.toml
- `--channels-only` — only repair channel configuration
- `--reinit` — start fresh (backs up existing config)

Creates `~/.opsclaw/config.toml` with `0600` permissions.

---

## Status & Diagnostics

```bash
opsclaw status                    # System overview
opsclaw doctor                    # Run all diagnostic checks
opsclaw doctor models             # Probe model connectivity
opsclaw doctor traces             # Query execution traces
```

---

## Memory

```bash
opsclaw memory list                              # List all entries
opsclaw memory list --category core --limit 10   # Filtered list
opsclaw memory get "some-key"                    # Get specific entry
opsclaw memory stats                             # Usage statistics
opsclaw memory clear --key "prefix" --yes        # Delete entries (requires --yes)
```

**Key flags:**
- `--category <name>` — filter by category (core, daily, conversation, custom)
- `--limit <n>` — limit results
- `--key <prefix>` — key prefix for clear operations
- `--yes` — skip confirmation (required for clear)

---

## Cron

```bash
opsclaw cron list                                                      # List all jobs
opsclaw cron add '0 9 * * 1-5' 'Good morning' --tz America/New_York   # Recurring (cron expr)
opsclaw cron add-at '2026-03-11T10:00:00Z' 'Remind me about meeting'  # One-time at specific time
opsclaw cron add-every 3600000 'Check server health'                   # Interval in milliseconds
opsclaw cron once 30m 'Follow up on that task'                         # Delay from now
opsclaw cron pause <id>                                                # Pause job
opsclaw cron resume <id>                                               # Resume job
opsclaw cron remove <id>                                               # Delete job
```

**Subcommands:**
- `add <cron-expr> <command>` — standard cron expression (5-field)
- `add-at <iso-datetime> <command>` — fire once at exact time
- `add-every <ms> <command>` — repeating interval
- `once <duration> <command>` — delay from now (e.g., `30m`, `2h`, `1d`)

---

## Providers & Models

```bash
opsclaw providers                                # List all 40+ supported providers
opsclaw models list                              # Show cached model catalog
opsclaw models refresh --all                     # Refresh catalogs from all providers
opsclaw models set anthropic/claude-sonnet-4-6   # Set default model
opsclaw models status                            # Current model info
```

Model routing in config.toml:
```toml
[[model_routes]]
hint = "reasoning"
provider = "openrouter"
model = "anthropic/claude-sonnet-4-6"
```

---

## Gateway & Daemon

```bash
opsclaw gateway                                 # Start HTTP gateway (foreground)
opsclaw gateway -p 8080 --host 127.0.0.1        # Custom port/host

opsclaw daemon                                  # Gateway + channels + scheduler + heartbeat
opsclaw daemon -p 8080 --host 0.0.0.0           # Custom bind
```

**Gateway defaults:**
- Port: 42617
- Host: 127.0.0.1
- Pairing required: true
- Public bind allowed: false

---

## Service Management

OS service lifecycle (systemd on Linux, launchd on macOS).

```bash
opsclaw service install     # Install as system service
opsclaw service start       # Start the service
opsclaw service status      # Check service status
opsclaw service stop        # Stop the service
opsclaw service restart     # Restart the service
opsclaw service uninstall   # Remove the service
```

**Logs:**
- macOS: `~/.opsclaw/logs/daemon.stdout.log`
- Linux: `journalctl -u opsclaw`

---

## Channels

Channels are configured in `config.toml` under `[channels]` and `[channels_config.*]`.

```bash
opsclaw channels list       # List configured channels
opsclaw channels doctor     # Check channel health
```

Supported channels (21 total): Telegram, Discord, Slack, WhatsApp (Meta), WATI, Linq (iMessage/RCS/SMS), Email (IMAP/SMTP), IRC, Matrix, Nostr, Signal, Nextcloud Talk, and more.

Channel config example (Telegram):
```toml
[channels]
telegram = true

[channels_config.telegram]
bot_token = "..."
allowed_users = [123456789]
```

---

## Security & Emergency Stop

```bash
opsclaw estop --level kill-all                              # Stop everything
opsclaw estop --level network-kill                          # Block all network access
opsclaw estop --level domain-block --domain "*.example.com" # Block specific domains
opsclaw estop --level tool-freeze --tool shell              # Freeze specific tool
opsclaw estop status                                        # Check estop state
opsclaw estop resume --network                              # Resume (may require OTP)
```

**Estop levels:**
- `kill-all` — nuclear option, stops all agent activity
- `network-kill` — blocks all outbound network
- `domain-block` — blocks specific domain patterns
- `tool-freeze` — freezes individual tools

Autonomy config in config.toml:
```toml
[autonomy]
level = "supervised"                           # read_only | supervised | full
workspace_only = true
allowed_commands = ["git", "cargo", "python"]
forbidden_paths = ["/etc", "/root", "~/.ssh"]
max_actions_per_hour = 20
max_cost_per_day_cents = 500
```

---

## Hardware Peripherals

```bash
opsclaw hardware discover                              # Find USB devices
opsclaw hardware introspect /dev/ttyACM0               # Probe device capabilities
opsclaw peripheral list                                # List configured peripherals
opsclaw peripheral add nucleo-f401re /dev/ttyACM0      # Add peripheral
opsclaw peripheral flash-nucleo                        # Flash STM32 firmware
opsclaw peripheral flash --port /dev/cu.usbmodem101    # Flash Arduino firmware
```

**Supported boards:** STM32 Nucleo-F401RE, Arduino Uno R4, Raspberry Pi GPIO, ESP32.

Attach to agent session: `opsclaw agent --peripheral nucleo-f401re:/dev/ttyACM0`

---

## Skills

```bash
opsclaw skills list         # List installed skills
opsclaw skills install <path-or-url>  # Install a skill
opsclaw skills audit        # Audit installed skills
opsclaw skills remove <name>  # Remove a skill
```

---

## Shell Completions

```bash
opsclaw completions zsh     # Generate Zsh completions
opsclaw completions bash    # Generate Bash completions
opsclaw completions fish    # Generate Fish completions
```

---

## Config File

Default location: `~/.opsclaw/config.toml`

Config resolution order (first match wins):
1. `OPSCLAW_CONFIG_DIR` environment variable
2. `OPSCLAW_WORKSPACE` environment variable
3. `~/.opsclaw/active_workspace.toml` marker file
4. `~/.opsclaw/config.toml` (default)
