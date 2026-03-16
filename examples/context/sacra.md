# Sacra — Catholic web app (Hetzner VPS, 159.69.92.65)

## Architecture
F# web application — event-sourced, Catholic liturgical content platform.

## Containers (all managed via Docker Compose at /opt/sacra/docker-compose.yml)
- `sacra-api` — F# API server, port 33000→8080. GraphQL + REST. Health: GET /health → {"status":"healthy"}
- `sacra-server` — Blazor/Bolero frontend, port 33100→8080
- `postgres` — PostgreSQL 16 + pgmq for event sourcing. Internal only.
- `seq` — Structured logging (Serilog), port 33200→80. API key: S6hEepqRYanyZkamKkm8
- `jaeger` — Distributed tracing (OTLP), port 33300→16686

## Normal behaviour
- All 5 containers should always be running
- API should respond to GET /health with 200 and {"status":"healthy"}
- Occasional CancellationTokenSource errors in CommandWorker on startup/shutdown — these are pre-existing and benign, ignore them
- Container uptimes of several days are normal — low uptime is suspicious
- Deploy happens manually — containers may briefly restart during deploys, don't alert immediately

## What to watch for
- Any container going down (Critical)
- API /health returning non-200 (Critical)
- postgres restarting unexpectedly (Critical — event sourcing data at risk)
- Disk usage above 80% on root filesystem (Warning)
- New unrecognised containers (Info)

## Access
- SSH as root (key stored in secret store as sacra-hetzner-key)
- Docker Compose file: /opt/sacra/docker-compose.yml
- Logs: docker logs <container> or via Seq at localhost:33200
