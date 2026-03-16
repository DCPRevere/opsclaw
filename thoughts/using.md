# Using

Thoughts about how we imagine users would use OpsClaw.

## Where OpsClaw runs

Two deployment models:

- **Sidecar on the target** — runs on the same VPS or node it monitors. Simplest setup, no SSH needed, reads logs and Docker socket directly. Downside: if the box dies, OpsClaw dies with it.
- **Remote / in-cluster** — runs on a separate VPS, a Pi at home, or as a pod in Kubernetes. SSHes into targets. Survives target failures. Required for multi-target setups.

For Kubernetes, OpsClaw could run as a Deployment with a ServiceAccount that has read access to pods/logs/events and exec access for remediation.

## Discovery scan

When OpsClaw first connects to a target (or on demand), it runs a scan to build a picture of what's there. The goal is to minimise upfront config — point OpsClaw at a box and let it figure out the stack.

What the scan looks for:

- Running processes and listening ports
- Docker socket / running containers and their images
- systemd services
- Log locations (`journalctl`, `/var/log`, container logs)
- Databases listening (Postgres, MySQL, Redis, etc.) and which ports
- Nginx/Caddy/HAProxy configs and the sites they serve
- Cron jobs
- Disk mounts and usage
- OS and kernel version

The scan produces a snapshot: "this is what I found." The user reviews it, corrects anything wrong, and optionally adds target context for things the scan can't infer (see below). OpsClaw stores the snapshot and uses it as baseline for future work.

Re-scanning periodically (or after a deploy) lets OpsClaw detect drift — "there's a new container running that wasn't here yesterday" or "port 8080 is no longer listening."

The scan should be read-only and non-invasive. No writes, no installs, no config changes. Just observation.

## SSH access

User generates a dedicated keypair for OpsClaw. The public key goes into `authorized_keys` on each target, ideally for a locked-down `opsclaw` user with a restricted shell or sudoers allowlist.

Config might look like:

```
[[targets]]
name = "prod-web-1"
host = "203.0.113.10"
user = "opsclaw"
key = "/etc/opsclaw/keys/prod-web-1"
```

Open question: should OpsClaw manage key rotation itself, or leave that to the user?

## Credentials and secrets

Secrets (API keys, DB passwords, SSH keys) need to live somewhere OpsClaw can read them but that isn't plaintext config. Options:

- Environment variables (simple, works with systemd/docker)
- A secrets file with restricted permissions (`600`)
- Integration with Vault, SOPS, or cloud KMS (heavier but proper)
- OpsClaw's own encrypted secret store (the `src/security/` module already has some of this)

The config file references secrets by name, not by value. OpsClaw resolves them at runtime.

## Log access

How OpsClaw reads logs depends on the target:

- **Docker** — `docker logs` via the Docker socket or API
- **systemd** — `journalctl` over SSH
- **Files** — tail `/var/log/whatever` over SSH
- **Kubernetes** — `kubectl logs` or the Kubernetes API
- **Cloud** — CloudWatch, Stackdriver, etc. via API (future)

OpsClaw needs to know which log sources exist for each target and how to access them. This could be explicit config or auto-discovered (look for Docker socket, check for systemd, scan `/var/log`).

## Database access

Read-only access for diagnostics — connection counts, slow queries, replication lag, table sizes. Not for running migrations or writing data.

User provides a connection string (or secret reference) per database. OpsClaw connects with a read-only role.

```
[[targets.databases]]
name = "main-postgres"
type = "postgres"
dsn_secret = "prod-pg-readonly"
```

Open question: should OpsClaw ever have write access? Even for things like `pg_terminate_backend` on a runaway query? Probably needs an autonomy level gate.

## Target context

The model already knows how Postgres, Nginx, Redis etc. work. What it doesn't know is the specifics of *your* setup — non-default ports, unusual paths, database names, which replica is which. Discovery can find a lot, but it can't infer naming conventions or intent.

Users provide freeform context per target. This gets loaded into the model's context whenever OpsClaw is working on that target. No schema, no structured fields — just notes, because the weird stuff is always freeform.

```
[[targets]]
name = "prod-web-1"
host = "203.0.113.10"
user = "opsclaw"
key = "/etc/opsclaw/keys/prod-web-1"
context = """
Postgres runs on port 5433 (not default).
Main DB: app_prod, read replica: app_ro.
Nginx config is in /opt/nginx/conf, not /etc/nginx.
The app logs to /var/log/myapp/, not stdout.
Redis is used for sessions only, not caching — don't restart it lightly.
"""
```

Could also be a separate file per target (`context/prod-web-1.md`) for longer notes. The config field works for a few lines; a file works for a page.

This replaces the idea of "skill packs." The model is the skill layer — it just needs the site-specific knowledge that discovery can't reliably provide.

## Docker / container access

If running on the same host: mount the Docker socket. If remote: access the Docker API over SSH or TLS.

Capabilities: list containers, inspect, read logs, restart, stop. Possibly pull and redeploy (higher autonomy level).

## Autonomy levels

Not everything should be automatic. A rough model:

1. **Observe** — monitor and report only
2. **Suggest** — diagnose and recommend actions, wait for approval
3. **Act on known fixes** — apply remediations from the runbook automatically, report after
4. **Full auto** — investigate and fix novel issues autonomously

Each target or action category could have its own autonomy level. "Restart a crashed container" might be level 3, but "modify a database" stays at level 2.

## Notification and escalation

OpsClaw needs a way to reach the human when it can't (or shouldn't) fix something itself.

Channels: Telegram, Slack, Discord, email, webhook. No phone number required for any of these — Telegram and Discord use bot tokens, Slack uses a webhook or bot token, email uses SMTP credentials.

Multiple channels can be active at once with different roles. E.g. email for routine digests and low-priority warnings, Telegram for urgent alerts that need to hit the phone immediately.

Escalation path: try the primary on-call, wait N minutes, try the secondary. If nobody responds, keep retrying with increasing urgency.

## First-run experience

`opsclaw setup` — an interactive CLI session. No config file needed upfront, no docs to read first. The conversation happens in the terminal since no channels are configured yet.

The flow:

1. Where am I running? (same box / remote)
2. If remote: collect SSH details, test connection
3. Run discovery scan — show results, ask the user to confirm or correct
4. User adds target context for anything the scan can't infer
5. Choose autonomy level (observe / suggest / act on known / full auto)
6. Set up notification channels — walk through bot tokens, SMTP creds, webhook URLs
7. Store credentials via the secret store
8. Write config file, start monitoring

This extends ZeroClaw's existing `onboard` command, which already handles provider/model setup. `opsclaw setup` wraps it and adds target, scan, context, autonomy, and notification steps on top.
