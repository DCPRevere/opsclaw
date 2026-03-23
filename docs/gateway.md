# Gateway API

The gateway is an HTTP/WebSocket server embedded in OpsClaw. It exposes a REST API, a real-time WebSocket stream, and a webhook receiver. The web dashboard is also served from it.

## Starting the gateway

The gateway starts automatically with `opsclaw daemon`. To start it standalone:

```bash
opsclaw gateway start
```

Default address: `http://127.0.0.1:42617`

## Configuration

```toml
[gateway]
port = 42617
host = "127.0.0.1"
require_pairing = true          # Require paired token for API access
allow_public_bind = false       # Set true to bind 0.0.0.0
trust_forwarded_headers = false # Enable only behind a trusted reverse proxy
pair_rate_limit_per_minute = 10
webhook_rate_limit_per_minute = 60
idempotency_ttl_secs = 300
idempotency_max_keys = 10000
```

To expose the gateway externally (e.g. for webhooks), either set `allow_public_bind = true` or put a reverse proxy in front.

## Pairing

Before you can use the API, you need a paired token.

```bash
opsclaw gateway get-paircode     # Prints a pairing code / QR
```

Or via HTTP:

```
GET /pair
```

Returns a one-time pairing token. Complete pairing:

```
POST /pair
Content-Type: application/json
{"code": "<pairing-code>"}
```

Returns a `Bearer` token for subsequent requests.

## Authentication

All API endpoints (except `/pair` and `/webhook`) require:

```
Authorization: Bearer <token>
```

## REST endpoints

### System

```
GET /api/status
```
Returns agent status, active channels, target health, and uptime.

```
GET /api/config
```
Returns current config. The `api_key` field is masked as `***MASKED***`.

```
PUT /api/config
Content-Type: application/toml
```
Replace config from a TOML body. Restarts affected subsystems.

```
GET /api/tools
```
Lists all registered tool specs (name, description, parameters).

### Memory

```
GET /api/memory?query=nginx+crash&category=incident&limit=10
```
Search memory. All query parameters are optional.

```
POST /api/memory
Content-Type: application/json
{"content": "...", "category": "note"}
```
Store a memory entry.

### Cron

```
GET /api/cron?limit=10
```
List recent cron job runs.

```
POST /api/cron
Content-Type: application/json
{"expression": "0 9 * * 1-5", "prompt": "Morning health check"}
```
Add a cron job.

## WebSocket

Connect to `ws://127.0.0.1:42617/ws` with a `Bearer` token to receive real-time events:

```
GET /ws
Upgrade: websocket
Authorization: Bearer <token>
```

Events are JSON-encoded and include:

- Agent status changes
- Tool execution start/end
- Incident creation and resolution
- Memory writes
- Escalation triggers

## Webhook receiver

```
POST /webhook
```

Ingests external events (alerts from Prometheus, GitHub, PagerDuty, etc.) and dispatches them to the agent.

- Configurable path via `[channels_config.webhook].listen_path`
- HMAC-SHA256 signature verification (set `secret` in webhook channel config)
- Idempotency key deduplication: include `X-Idempotency-Key` header to prevent duplicate processing

## Reverse proxy example (nginx)

```nginx
server {
    listen 443 ssl;
    server_name opsclaw.example.com;

    location / {
        proxy_pass http://127.0.0.1:42617;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Set `trust_forwarded_headers = true` in `[gateway]` when behind a trusted proxy.

## Agent-to-Agent (A2A)

The gateway also serves an A2A protocol endpoint using JSON-RPC 2.0 over HTTP. This allows multiple OpsClaw instances to discover and delegate tasks to each other.

```bash
opsclaw a2a server              # Start A2A server (part of daemon)
opsclaw a2a discover            # Find peers on the network
opsclaw a2a peers               # List known peers
opsclaw a2a send <peer> "task"  # Delegate a task to a peer
opsclaw a2a status              # Show A2A connectivity
```
