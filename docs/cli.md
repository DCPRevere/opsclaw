# CLI Reference

## Inherited from zeroclaw

These commands come from the upstream zeroclaw runtime. They are not SRE-specific.

**`onboard`** — first-run setup wizard. Configures your AI provider, API key, memory backend, and communication channels. Run this once when setting up a new machine.

**`agent`** — starts an interactive chat session with the configured LLM. Use for ad-hoc queries or single-shot messages (`-m`). The SRE tools are available to the agent during a session.

**`gateway`** — starts the HTTP/WebSocket gateway that accepts incoming webhooks and pairs with the desktop companion app. Required for channel integrations and remote triggering.

**`acp`** — starts an Agent Control Protocol server over stdio. Used for programmatic agent-to-agent communication.

**`daemon`** — starts the full autonomous runtime: gateway, all channels, heartbeat, and cron scheduler together. This is how you run opsclaw in production or as a background service.

**`service`** — installs or removes the daemon as a systemd/launchd user service so it starts automatically on boot.

**`doctor`** — runs diagnostics: checks that the daemon is alive, channels are fresh, models are reachable, and the scheduler is ticking. Run this when something seems broken.

**`status`** — shows a full system status snapshot: gateway health, active channels, scheduled tasks, and connected projects.

**`estop`** — emergency stop. Immediately freezes agent actions at a chosen level (kill all, network kill, domain block, tool freeze). Use when the agent is doing something it shouldn't. `estop resume` lifts the stop.

**`cron`** — manages the built-in task scheduler. Add, list, pause, and remove scheduled agent tasks or shell commands using cron expressions, intervals, or one-shot timestamps.

**`models`** — manages the local model catalog. Refresh available models from a provider, list them, or set the default.

**`providers`** — lists all supported AI providers (OpenRouter, Anthropic, OpenAI, etc.) with their capabilities.

**`channel`** — manages communication channels: Telegram, Discord, Slack, WhatsApp, Matrix, email. Add, remove, health-check, and send messages.

**`integrations`** — browses the 50+ available integrations (GitHub, Linear, Jira, Notion, etc.) and shows configuration instructions.

**`skills`** — manages user-defined agent capabilities. Add, remove, and list skills that extend what the agent can do.

**`migrate`** — imports agent memory and configuration from other runtimes (e.g. OpenClaw).

**`auth`** — manages provider OAuth profiles. Login, logout, refresh tokens, and switch between profiles for providers like OpenAI Codex and Gemini.

**`hardware`** — discovers and introspects connected USB development boards (STM32, Arduino, ESP32).

**`peripheral`** — manages hardware peripherals that expose tools to the agent (GPIO, sensors, actuators).

**`memory`** — lists, inspects, and clears agent memory entries. Useful for debugging what the agent remembers between sessions.

**`config`** — inspects and edits configuration. Subcommands:

- `config schema` — dumps the full JSON Schema for `config.toml`.
- `config target {add|list|remove|context|context-edit|show}` — manages flat targets (the legacy non-hierarchical form). A target is a monitored endpoint: a remote server, a local machine, or a Kubernetes cluster. `config target add` walks you through an interactive wizard.
- `config project {add|list|remove|show}` — manages top-level projects in the hierarchical layout (see [`hierarchy.md`](hierarchy.md) and [`projects.md`](projects.md)). A project wraps one or more environments.
- `config env {add|list|remove|show}` — manages environments within a project. Address form is `project::env` (e.g. `config env remove shopfront::dev`). `config env add` prompts for the parent project; when only one project is configured it is auto-selected.
- `config get <path>` / `config set <path> <value>` — read or write individual properties inherited from the upstream zeroclaw config schema.
- `config schema` — see above.

Flat targets (`config target`) and hierarchical projects (`config project` + `config env`) are mutually exclusive — pick one shape per config file.

**`update`** — checks for and installs a new opsclaw release.

**`self-test`** — runs diagnostic self-tests to verify the installation: memory round-trip, gateway health, provider connectivity.

**`completions`** — generates shell completion scripts for bash, zsh, fish, PowerShell, or elvish.

**`desktop`** — launches or downloads the companion desktop/menu-bar app.

---

## OpsClaw SRE commands

These commands are specific to OpsClaw's SRE role. They operate on targets (monitored endpoints in `config.toml`) and, in the hierarchical layout, on projects and environments.

Target / project / environment management lives under `config` — see the **`config`** entry above. In short: `config target` for the flat layout, `config project` + `config env` for the hierarchical layout.

**`scan`** — connects to a project (via SSH or locally) and takes an inventory snapshot: OS, running containers, systemd units, open ports, disk, memory, load. Saves the result to `~/.opsclaw/snapshots/<project>.json`. The first scan establishes the baseline that `monitor` compares future scans against.

**`monitor`** — runs the monitoring loop. Periodically scans each project and compares the result against the baseline. When anomalies are detected it invokes the LLM to diagnose, records an incident, and optionally remediates. This is the core autonomous SRE loop.

**`logs`** — collects recent log lines from Docker containers, systemd units, and log files on a project. Useful for pulling logs without SSHing in, especially when investigating an incident the agent flagged.

**`baseline`** — shows the rolling metric statistics (mean, stddev, trend) that `monitor` uses for anomaly detection. Use `--reset` to clear baseline data after intentional infrastructure changes so monitor doesn't keep alerting on the new normal.

**`incidents`** — lists, searches, and resolves incidents recorded by `monitor`. Use this to review what the agent found, search for past occurrences of a problem, or mark an incident resolved once fixed.

**`runbook`** — manages remediation runbooks: step-by-step procedures the agent can execute when it detects a known class of problem. `runbook init` installs the built-in defaults; `runbook run` executes one manually against a project.

**`digest`** — generates a summary report of monitoring activity across all projects for a rolling time window (default 24 hours): incidents, anomalies, health trends. Use `--notify` to send it via the configured channel.

**`postmortem`** — generates a structured Markdown post-mortem report for a recorded incident, including timeline, diagnosis, and resolution. Output goes to stdout or a file.
