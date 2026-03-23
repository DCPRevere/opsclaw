# Configuration

OpsClaw is configured via `~/.opsclaw/opsclaw.toml`. This page covers all sections and keys.

Run `opsclaw config schema` to dump the full JSON Schema.

## Root level

```toml
workspace_dir = "~/.opsclaw"
default_provider = "openrouter"
default_model = "anthropic/claude-sonnet-4"
default_temperature = 0.7       # 0.0–2.0
provider_timeout_secs = 120
api_key = "sk-..."              # Fallback key if provider has none
api_url = "https://..."         # Optional base URL override
api_path = "/v1/chat/completions"
```

## [[targets]]

Each system OpsClaw monitors is a target. You can have multiple.

```toml
[[targets]]
name = "prod-web-1"
type = "ssh"           # ssh | local | kubernetes
host = "203.0.113.10"
port = 22              # Default: 22
user = "opsclaw"
key_secret = "prod-web-1-key"   # Encrypted secret name
autonomy = "suggest"            # readonly | supervised | full
context_file = "~/.opsclaw/context/prod-web-1.md"

[targets.probes]
url = "https://example.com/health"
interval_secs = 60
timeout_secs = 10
```

For Kubernetes targets, see the [k8s docs](k8s.md).

For local targets, omit `host`, `port`, `user`, and `key_secret`.

## [gateway]

The HTTP/WebSocket server used for webhooks and the web dashboard.

```toml
[gateway]
port = 42617
host = "127.0.0.1"
require_pairing = true          # Require paired token for API access
allow_public_bind = false       # Set true to bind 0.0.0.0
pair_rate_limit_per_minute = 10
webhook_rate_limit_per_minute = 60
trust_forwarded_headers = false # Enable only behind a trusted reverse proxy
rate_limit_max_keys = 10000
idempotency_ttl_secs = 300
idempotency_max_keys = 10000
```

## [memory]

Controls where and how long OpsClaw retains conversations and knowledge.

```toml
[memory]
backend = "sqlite"              # sqlite | postgres | lucid | qdrant | markdown | none
auto_save = true
hygiene_enabled = true
archive_after_days = 7
purge_after_days = 30
conversation_retention_days = 30

# Semantic search (optional)
embedding_provider = "none"     # none | openai | custom:URL
embedding_model = "text-embedding-3-small"
embedding_dimensions = 1536
vector_weight = 0.7             # 0.0–1.0 (must sum to 1.0 with keyword_weight)
keyword_weight = 0.3
min_relevance_score = 0.4       # Memories below this score are excluded
embedding_cache_size = 10000
chunk_max_tokens = 512

# Response deduplication cache
response_cache_enabled = false
response_cache_ttl_minutes = 60
response_cache_max_entries = 5000
response_cache_hot_entries = 256

# Snapshot memory to markdown files
snapshot_enabled = false
snapshot_on_hygiene = false
auto_hydrate = true
```

See [memory docs](memory.md) for backend-specific options.

## [autonomy]

Fine-grained control over what the agent is allowed to do.

```toml
[autonomy]
level = "supervised"            # readonly | supervised | full
workspace_only = true           # Restrict file ops to workspace_dir
allowed_commands = ["git", "cargo", "npm", "ls", "cat", "grep", "find", "df", "ps", "docker", "kubectl"]
forbidden_paths = ["/etc", "/root", "~/.ssh", "~/.gnupg"]
max_actions_per_hour = 100
max_cost_per_day_cents = 1000
require_approval_for_medium_risk = true
block_high_risk_commands = true
auto_approve = ["file_read", "memory_recall"]
always_ask = []
shell_env_passthrough = []
```

See [autonomy & escalation docs](autonomy.md) for details on each level.

## [channels_config]

Global channel settings and per-channel configuration. See [channels docs](channels.md) for all supported types.

```toml
[channels_config]
cli = true                      # Enable terminal channel
message_timeout_secs = 300
ack_reactions = true            # React to messages with 👀/✅/⚠️
show_tool_calls = true
session_persistence = true
session_backend = "sqlite"      # sqlite | jsonl
session_ttl_hours = 0           # 0 = no auto-archive

[channels_config.telegram]
bot_token = "${TELEGRAM_BOT_TOKEN}"
allowed_users = ["alice", "123456789"]
stream_mode = "off"             # off | partial
interrupt_on_new_message = false
mention_only = false
```

## [[cron]]

Scheduled agent tasks. See `opsclaw cron --help` for CLI alternatives.

```toml
[[cron]]
expression = "0 9 * * 1-5"     # Standard 5-field cron (UTC by default)
tz = "Europe/London"            # Optional timezone
agent_prompt = "Good morning — check system health and summarise overnight incidents"

[[cron]]
expression = "*/30 * * * *"
agent_prompt = "Check disk usage on all targets"
tool_allowlist = ["disk_check", "memory_recall"]  # Restrict available tools
```

## [escalation]

```toml
[escalation]
enabled = true
ack_timeout_secs = 300          # 5 minutes before escalating to next contact
repeat_interval_secs = 900      # Re-notify every 15 minutes

[[escalation.contacts]]
name = "Alice"
channel = "telegram"
target = "123456789"            # Chat ID
priority = 0                    # 0 = first notified

[[escalation.contacts]]
name = "Bob"
channel = "slack"
target = "U0XXXXXXX"           # Slack user ID
priority = 1
```

## Environment variables

All config keys can be overridden via environment variables:

| Variable | Purpose |
|---|---|
| `OPSCLAW_CONFIG_DIR` | Config directory (default: `~/.opsclaw`) |
| `OPSCLAW_PROVIDER` | Default provider |
| `OPSCLAW_MODEL` | Default model |
| `OPSCLAW_TEMPERATURE` | Default temperature |
| `OPSCLAW_API_KEY` | Fallback API key |
| `OPSCLAW_GATEWAY_PORT` | Gateway port |
| `OPSCLAW_GATEWAY_HOST` | Gateway host |
| `OPSCLAW_WORKSPACE` | Workspace directory |
| `RUST_LOG` | Log level (`info`, `debug`, `warn`, `error`) |
