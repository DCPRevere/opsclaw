# OpsClaw Docker Sandbox

Fully isolated Docker environment for testing OpsClaw in both remote and sidecar deployment modes. OpsClaw runs inside containers — never on the host.

## Quick start

```
cd dev/sandbox
./run-tests.sh
```

Set `OPSCLAW_LLM_API_KEY` in your environment if you want real LLM calls (defaults to `test`).

## Architecture

All containers run on an internal Docker network (`sandbox-net`) with no internet access.

### Services

| Container | Role |
|---|---|
| sandbox-sshd | SSH target with Docker CLI and journalctl stub |
| sandbox-app | nginx serving a test page |
| sandbox-db | PostgreSQL 16 |
| sandbox-seq | Seq log aggregator |
| sandbox-jaeger | Jaeger tracing |
| opsclaw-remote | OpsClaw in remote mode (SSHes into sandbox-sshd) |
| opsclaw-sidecar | OpsClaw in sidecar mode (has Docker socket) |

### Two modes

**Remote mode** (`opsclaw-remote`): OpsClaw connects to the target over SSH. This mirrors production deployments where OpsClaw runs on a separate machine.

**Sidecar mode** (`opsclaw-sidecar`): OpsClaw has direct Docker socket access. This mirrors deployments where OpsClaw runs alongside the workload on the same host.

## Extending

Add new test scenarios to `run-tests.sh`. Each test follows the pattern:

1. Print a test header
2. Run an opsclaw command via `docker compose exec`
3. Print PASSED on success (the script uses `set -e` so failures abort)

To add new services, add them to `docker-compose.yml` on the `sandbox-net` network.
