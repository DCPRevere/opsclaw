# My App — Production Server

## Architecture
Containerised web application running on a Linux VPS.

## Containers
- `myapp-api` — API server, port 8080. Health: GET /health → 200 OK
- `myapp-web` — Frontend, port 3000
- `postgres` — Database. Internal only.

## Normal behaviour
- All containers should always be running
- API should respond to /health with 200
- Container uptimes of several days are normal
- Deploys cause brief restarts — don't alert immediately

## What to watch for
- Any container going down (Critical)
- API /health returning non-200 (Critical)
- postgres restarting unexpectedly (Critical)
- Disk usage above 80% (Warning)
- Unexpected new containers (Info)

## Access
- SSH as deploy user (key stored in secret store as myapp-ssh-key)
- Docker Compose file: /opt/myapp/docker-compose.yml
