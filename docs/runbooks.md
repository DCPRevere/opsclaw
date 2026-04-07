# Runbooks

Runbooks are structured remediation procedures. When OpsClaw detects an incident that matches a runbook's trigger, it can execute the steps automatically (at `act_on_known` or `full` autonomy) or propose them for approval (at `supervised`).

## Creating a runbook

```bash
opsclaw runbook init container-oom
```

This creates `~/.opsclaw/runbooks/container-oom.md` from a template. Edit it to define the trigger and steps.

Or list and view existing runbooks:

```bash
opsclaw runbook list
opsclaw runbook show container-oom
```

## Runbook format

Runbooks are markdown files with a TOML front matter block:

```markdown
---
name = "container-oom"
description = "Restart a container that has been OOM-killed"

[trigger]
alert_categories = ["ContainerOOM", "OOMKilled"]
keywords = ["out of memory", "oom"]
target_pattern = "prod-*"          # Glob: which targets this applies to
---

# Container OOM

This runbook handles containers killed by the kernel OOM killer.

## Steps

1. Confirm the container has been OOM-killed:
   `docker inspect {container} --format '{{.State.OOMKilled}}'`

2. Check recent memory usage:
   `docker stats {container} --no-stream`

3. Restart the container:
   `docker restart {container}`

4. Verify it came back healthy:
   `docker ps --filter name={container}`
```

## Trigger matching

A runbook is triggered when all specified conditions match an incoming alert:

- **`alert_categories`** — matches the alert's type (e.g. `ContainerOOM`, `ServiceStopped`, `DiskFull`, `HighCPU`)
- **`keywords`** — case-insensitive substrings in the alert message
- **`target_pattern`** — glob applied to the target name (`prod-*`, `*-k8s`, `"*"` for all)

If multiple runbooks match the same alert, all are presented; the agent picks the most specific one.

## Command placeholders

Commands in runbook steps can include placeholders that are resolved at execution time:

| Placeholder | Value |
|---|---|
| `{target}` | Target name (e.g. `prod-web-1`) |
| `{container}` | Container name extracted from alert |
| `{service}` | Service name extracted from alert |
| `{namespace}` | Kubernetes namespace |
| `{timestamp}` | RFC 3339 execution timestamp |

## Step failure handling

Each step can specify what happens on failure (in TOML front matter or inferred from markdown):

- **Abort** — stop the runbook and report failure (default for high-risk steps)
- **Continue** — log the failure and move to the next step
- **Retry** — retry the step up to N times with a delay

For simple markdown runbooks, OpsClaw's LLM layer interprets the prose and infers appropriate failure handling.

## Running a runbook manually

```bash
opsclaw runbook run container-oom --target prod-web-1
```

Pass extra context:

```bash
opsclaw runbook run container-oom --target prod-web-1 --var container=api-server
```

## Execution tracking

Each run is recorded with:

- Start/end time
- Steps completed
- Output of each command
- Success or failure per step
- Overall outcome

View run history:

```bash
opsclaw runbook show container-oom --history
```

Over time, OpsClaw tracks the `success_rate` per runbook and surfaces runbooks with low success rates for review.

## Runbooks and autonomy

At `supervised` autonomy, runbook execution still requires approval before each mutating step. To allow a runbook to run fully automatically at `supervised` level, add it to the `auto_approve` list:

```toml
[autonomy]
auto_approve = ["runbook:container-oom", "runbook:disk-cleanup"]
```

At `full` autonomy, all runbooks execute without approval.
