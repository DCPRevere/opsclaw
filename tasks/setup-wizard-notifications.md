# Setup wizard: only Telegram notifications wired

`ops/setup.rs:443-448` lists Slack, Email, and Webhook as "coming soon". The wizard should configure at least Slack and generic webhook, since ZeroClaw already has channel adapters for both.
