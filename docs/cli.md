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

**`config`** — inspects configuration. Currently exposes `config schema` to dump the full JSON Schema for `config.toml`.

**`update`** — checks for and installs a new opsclaw release.

**`self-test`** — runs diagnostic self-tests to verify the installation: memory round-trip, gateway health, provider connectivity.

**`completions`** — generates shell completion scripts for bash, zsh, fish, PowerShell, or elvish.

**`desktop`** — launches or downloads the companion desktop/menu-bar app.

---

## OpsClaw SRE commands

These commands are specific to OpsClaw's SRE role. They all operate on projects (monitored environments defined in `config.toml`).

**`project`** — manages projects. A project is a monitored environment: a remote server, a local machine, or a Kubernetes cluster. Subcommands:
- `project add` — interactive wizard to add a new project (name, connection type, SSH details, autonomy level)
- `project list` — lists all configured projects
- `project remove <name>` — removes a project from config
- `project context <name>` — prints the project's context file
- `project context-edit <name>` — opens the project's context file in `$EDITOR`. The context file is Markdown that describes the project to the agent: what runs on it, what normal looks like, who owns it.

**`scan`** — connects to a project (via SSH or locally) and takes an inventory snapshot: OS, running containers, systemd units, open ports, disk, memory, load. Saves the result to `~/.opsclaw/snapshots/<project>.json`. The first scan establishes the baseline that `monitor` compares future scans against.

**`monitor`** — runs the monitoring loop. Periodically scans each project and compares the result against the baseline. When anomalies are detected it invokes the LLM to diagnose, records an incident, and optionally remediates. This is the core autonomous SRE loop.

**`logs`** — collects recent log lines from Docker containers, systemd units, and log files on a project. Useful for pulling logs without SSHing in, especially when investigating an incident the agent flagged.

**`baseline`** — shows the rolling metric statistics (mean, stddev, trend) that `monitor` uses for anomaly detection. Use `--reset` to clear baseline data after intentional infrastructure changes so monitor doesn't keep alerting on the new normal.

**`incidents`** — lists, searches, and resolves incidents recorded by `monitor`. Use this to review what the agent found, search for past occurrences of a problem, or mark an incident resolved once fixed.

**`runbook`** — manages remediation runbooks: step-by-step procedures the agent can execute when it detects a known class of problem. `runbook init` installs the built-in defaults; `runbook run` executes one manually against a project.

**`digest`** — generates a summary report of monitoring activity across all projects for a rolling time window (default 24 hours): incidents, anomalies, health trends. Use `--notify` to send it via the configured channel.

**`postmortem`** — generates a structured Markdown post-mortem report for a recorded incident, including timeline, diagnosis, and resolution. Output goes to stdout or a file.
