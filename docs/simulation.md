# Simulation Environment

A Docker-based environment for testing OpsClaw's monitoring pipeline end-to-end. OpsClaw runs for real, SSHes into a simulated target, and reacts to injected faults by sending webhook notifications.

## Quick start

```bash
./dev/sim/sim.sh up           # build, start containers, establish baseline
./dev/sim/sim.sh fault memory  # inject memory pressure
./dev/sim/sim.sh webhooks      # see the alert OpsClaw sent
./dev/sim/sim.sh clear         # return to healthy
./dev/sim/sim.sh down          # tear down
```

## How it works

OpsClaw discovers system state by SSHing into a host and running commands like `free -m`, `df -h`, `uptime`, `docker ps`, `ss -tlnp`, and `systemctl list-units`. The sim-target container intercepts these commands with wrapper scripts in `/usr/local/bin/` that check for an active scenario file. When a fault is injected, the wrappers return crafted output (e.g. 95% memory usage) instead of real data.

OpsClaw then diffs the scan against its stored baseline and fires alerts through the `WebhookNotifier`, which POSTs JSON to a local webhook-sink container that captures every notification.

## Available faults

| Command | What it simulates | Expected alert |
|---|---|---|
| `fault memory` | 95% memory used | HighMemory (Warning) |
| `fault disk` | /data at 92% | DiskSpaceLow (Critical) |
| `fault load` | Load average 12.5 | HighLoad (Warning) |
| `fault container` | API container gone | ContainerDown (Critical) |
| `fault restart` | API container restarted | ContainerRestarted (Warning) |
| `fault service` | nginx.service stopped | ServiceStopped (Critical) |
| `fault port` | Port 3000 gone | PortGone (Warning) |
| `fault crisis` | Memory + disk + container | Multiple alerts |

## Commands

- `up` -- Start Docker containers, build OpsClaw, establish baseline, start monitor daemon (30s interval)
- `down` -- Stop everything, clean state
- `fault <name>` -- Inject a fault scenario
- `clear` -- Reset to healthy baseline
- `status` -- Current scenario, recent logs, recent webhooks
- `logs` -- Tail OpsClaw monitor output
- `webhooks` -- Show all captured webhook notifications
- `test` -- Run all scenarios automatically with pass/fail

## Architecture

```
dev/sim/
  sim.sh              CLI orchestrator
  docker-compose.yml   sim-target + webhook-sink (host networking)
  sim-target/          Ubuntu 22.04 + openssh-server + command wrappers
  webhook-sink/        Python HTTP server capturing POSTs as JSONL
  scenarios/           Bash scripts defining fake command output per fault
  .state/              Runtime state (gitignored): logs, keys, config, webhooks
```

The sim-target container has no Docker engine or systemd. The baseline scenario provides fake output for those commands so OpsClaw sees containers and services. Fault scenarios override specific command outputs on top of the baseline.

## Adding a new scenario

Create `dev/sim/scenarios/myfault.sh`:

```bash
source /sim/scenarios/baseline.sh

sim_free() {
    cat <<'EOF'
               total        used        free      shared  buff/cache   available
Mem:            8000        7200         200         128         600         700
Swap:           2048         800        1248
EOF
}
```

Then run `./dev/sim/sim.sh fault myfault`.

## Webhook payload format

Each notification is a JSON object:

```json
{
  "type": "health_check",
  "target": "sim-target",
  "status": "Warning",
  "alerts": [
    {
      "severity": "Warning",
      "category": "HighMemory",
      "message": "Memory usage at 95% (7600/8000 MB)"
    }
  ]
}
```

Payloads are appended to `.state/requests.jsonl` (one per line) and logged to the webhook-sink stdout.
