# Autonomy and escalation

OpsClaw's autonomy system controls how much it can act without human approval. Escalation determines who gets notified when something goes wrong and how long to wait for a response.

## Autonomy levels

Set per-target in `opsclaw.toml`:

```toml
[[targets]]
name = "prod-web-1"
autonomy = "supervised"   # readonly | supervised | full
```

### readonly

The agent observes, diagnoses, and reports — but never writes anything to the target.

- All read commands execute normally: `ls`, `cat`, `grep`, `df`, `ps`, `docker ps`, `kubectl get`, etc.
- All mutating commands are blocked and logged to `~/.opsclaw/dry-run.log`
- Useful for first connecting to a new target, or for highly sensitive systems

Review what would have run:

```bash
opsclaw dry-run-log
```

### supervised (default)

The agent acts but asks for approval before medium- and high-risk commands.

- Low-risk reads auto-execute
- Medium-risk commands (restart a service, delete a file) trigger an approval request via your configured channel
- High-risk commands are blocked unless explicitly approved
- Approval timeout set by `message_timeout_secs` (default: 300s); cancels if no reply

Customise what's auto-approved and what always requires confirmation:

```toml
[autonomy]
auto_approve = ["file_read", "memory_recall", "disk_check"]
always_ask = ["restart_service", "delete_file"]
```

### full

Fully autonomous within policy bounds. No approval prompts.

- All allowed commands execute without asking
- Still subject to `forbidden_paths`, `max_actions_per_hour`, and `max_cost_per_day_cents`
- Appropriate for dev/staging environments or well-understood production runbooks

## Policy constraints

These apply at all autonomy levels:

```toml
[autonomy]
workspace_only = true           # File operations restricted to workspace_dir
forbidden_paths = ["/etc", "/root", "~/.ssh", "~/.gnupg"]
allowed_commands = ["git", "cargo", "npm", "ls", "cat"]
max_actions_per_hour = 100
max_cost_per_day_cents = 1000   # Approximate LLM spend limit
block_high_risk_commands = true # Always block destructive ops (rm -rf, etc.)
```

## Emergency stop

Immediately freeze all agent action across all targets:

```bash
opsclaw estop                   # Freeze — no commands will execute
opsclaw estop status            # Check freeze state
opsclaw estop resume            # Unfreeze
```

E-stop also supports network-kill (drops all outbound connections) and domain-block modes.

## Escalation

When OpsClaw detects an incident and cannot resolve it autonomously, it escalates to your contacts in priority order.

### Configuration

```toml
[escalation]
enabled = true
ack_timeout_secs = 300          # Time to wait for acknowledgement (5 min)
repeat_interval_secs = 900      # Re-notify if no ack after this interval (15 min)

[[escalation.contacts]]
name = "Alice"
channel = "telegram"
target = "123456789"            # Telegram chat ID
priority = 0                    # 0 is notified first

[[escalation.contacts]]
name = "Bob"
channel = "slack"
target = "U0XXXXXXX"
priority = 1

[[escalation.contacts]]
name = "ops-team"
channel = "email"
target = "ops@example.com"
priority = 2
```

### Escalation flow

1. Incident detected → first contact (priority 0) is notified
2. Agent waits `ack_timeout_secs` for acknowledgement
3. No ack → escalate to next priority contact
4. After ack → agent waits for resolution details
5. Every `repeat_interval_secs` → re-notifies current contact if still unresolved
6. All contacts exhausted with no ack → incident marked as `Expired`

### Incident states

| State | Meaning |
|---|---|
| `Active` | Detected, waiting for acknowledgement |
| `Acknowledged` | Someone has taken ownership |
| `Resolved` | Closed with resolution text |
| `Expired` | All contacts exhausted |

### Reviewing incidents

```bash
opsclaw incidents               # List all incidents
opsclaw incidents --state active  # Filter by state
opsclaw postmortem <incident-id>  # Generate structured postmortem report
```

## Runbooks and autonomy

Runbooks let OpsClaw act autonomously for known scenarios even at `supervised` level — the runbook serves as pre-approval. See [runbooks docs](runbooks.md).
