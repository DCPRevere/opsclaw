# Channels

Channels are how OpsClaw communicates with you — for alerts, approvals, and interactive chat. Configure them in `[channels_config]` in `opsclaw.toml`.

## Common settings

```toml
[channels_config]
cli = true                      # Terminal channel (always available)
message_timeout_secs = 300      # How long to wait for a reply
ack_reactions = true            # React with 👀 on receipt, ✅ on done, ⚠️ on error
show_tool_calls = true          # Show tool use in responses
session_persistence = true
session_backend = "sqlite"      # sqlite | jsonl
session_ttl_hours = 0           # 0 = sessions never auto-archive
```

## Telegram

```toml
[channels_config.telegram]
bot_token = "${TELEGRAM_BOT_TOKEN}"   # From @BotFather
allowed_users = ["alice", "123456789"]  # Usernames or numeric chat IDs
stream_mode = "off"             # off | partial (progressive edits)
draft_update_interval_ms = 1000 # Minimum time between partial edits
interrupt_on_new_message = false
mention_only = false            # Only respond to @-mentions in groups
```

Telegram is the recommended channel for approvals — OpsClaw sends inline buttons for approve/reject on supervised actions.

To set up:
1. Create a bot via [@BotFather](https://t.me/botfather) and copy the token.
2. Start a chat with your bot and send `/start` to get your chat ID, or use `opsclaw channel bind-telegram`.
3. Add your chat ID to `allowed_users`.

## Slack

```toml
[channels_config.slack]
bot_token = "xoxb-..."          # Bot OAuth token
app_token = "xapp-..."          # Optional: Socket Mode app token
channel_id = "C123ABC"          # Optional: restrict to one channel
allowed_users = ["U123ABC"]     # Slack user IDs
interrupt_on_new_message = false
mention_only = false
```

To set up, create a Slack app with the `chat:write`, `channels:history`, and `im:history` scopes. For Socket Mode (no public URL needed), enable it and generate an app-level token.

## Discord

```toml
[channels_config.discord]
bot_token = "..."
guild_id = "123456789"          # Optional: restrict to one guild
allowed_users = []              # Discord user IDs; empty = all members
listen_to_bots = false
mention_only = false
```

## Webhook

Generic HTTP webhook for sending and receiving events from any system:

```toml
[channels_config.webhook]
port = 5000
listen_path = "/webhook"        # Path to listen on inbound
send_url = "https://example.com/webhook"  # Optional: outbound target
send_method = "POST"            # POST | PUT
auth_header = "Bearer mytoken"  # Optional Authorization header on outbound
secret = "shared-secret"        # Optional: HMAC-SHA256 verification on inbound
```

## Email

```toml
[channels_config.email]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_user = "opsclaw@example.com"
smtp_password = "${EMAIL_PASSWORD}"
from_address = "opsclaw@example.com"
to_address = "oncall@example.com"
imap_host = "imap.example.com"  # Optional: for reading replies
imap_user = "opsclaw@example.com"
imap_password = "${EMAIL_PASSWORD}"
```

## Matrix

```toml
[channels_config.matrix]
homeserver = "https://matrix.example.com"
access_token = "..."
room_id = "!roomid:example.com"
allowed_users = ["@alice:example.com"]
```

## Other channels

OpsClaw also supports:

| Channel | Config key |
|---|---|
| Mattermost | `mattermost` |
| WhatsApp Cloud API | `whatsapp` |
| Lark / Feishu | `lark`, `feishu` |
| DingTalk | `dingtalk` |
| WeCom | `wecom` |
| Nextcloud Talk | `nextcloud` |
| IRC | `irc` |
| Nostr | `nostr` |
| Twitter/X | `twitter` |
| Signal | `signal` |
| iMessage (macOS) | `imessage` |

See `opsclaw integrations` for the full list.

## Managing channels via CLI

```bash
opsclaw channel list             # Show configured channels
opsclaw channel add telegram     # Interactive setup
opsclaw channel doctor telegram  # Test connectivity
opsclaw channel send telegram "Test alert"  # Send a test message
opsclaw channel remove telegram  # Remove a channel
```

## Approvals

When autonomy is set to `supervised`, OpsClaw sends approval requests before executing medium- or high-risk actions. On Telegram, these appear as inline buttons. On other channels, they're sent as a message with instructions to reply `approve` or `deny`.

Approval timeout is controlled by `message_timeout_secs` — if no reply is received, the action is cancelled.
