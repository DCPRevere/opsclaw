# Security

## OpsClaw audit

Perform an audit of your OpsClaw set up

## Audit log

OpsClaw logs every action it takes — every command run, every container restarted, every alert sent, every scan performed. This isn't optional or configurable. If OpsClaw did it, there's a record.

The audit log must be append-only. OpsClaw should never be able to modify or delete its own log entries. This matters because:

- Users need to trust that the log is a complete and truthful record of what OpsClaw did
- If OpsClaw is compromised or makes a mistake, the log is evidence
- For compliance use cases, an immutable audit trail is a hard requirement

### What gets logged

- Timestamp
- Action type (scan, command, restart, alert, config change, etc.)
- Target (which host, container, service)
- Detail (the actual command, the alert message, what was found)
- Autonomy level that permitted the action
- Outcome (success, failure, error)

### Append-only approaches

- **Simple:** write to a log file that OpsClaw's own process doesn't have permission to truncate or overwrite
- **Structured:** write to a local SQLite database where OpsClaw has INSERT but not UPDATE or DELETE
- **Hash chain:** each log entry includes a hash of the previous entry
- **Remote:** ship logs to an external system

### Exposing the log

Users should be able to review the audit log easily — via CLI (`opsclaw log`), via the notification channel ("show me what you did last night"), or via a future web dashboard. The log is always available and always honest.

## Least privilege

Create service accounts specifically for OpsClaw. Make them read-only by default, escalate only when autonomy mode requires it.

SSH user should have:
- Read access to Docker socket, journalctl, log files, system stats
- For `approve`/`auto` modes: sudo for specific commands only (e.g. `docker restart`, `systemctl restart`)
- Never root access unless absolutely required

OpsClaw warns during setup if the SSH user has broader permissions than the configured autonomy level needs.

## Autonomy modes

Three user-facing modes control what OpsClaw can do:

- **dry-run** — observe only, log proposed actions without executing. Default for evaluation.
- **approve** — propose actions, wait for user approval via notification channel (Telegram inline button, Slack reaction). Default for new targets.
- **auto** — execute remediations without asking. Opt-in only, after trust is established.

All modes log everything to the append-only audit trail. The audit trail is non-negotiable regardless of autonomy level.

Implementation: `SshCommandRunner` already has `is_read_only_command()`. Dry-run extends this to intercept all write commands. Approve mode adds an async approval gate (send notification, wait for response, then execute or skip). Auto mode removes the gate.

## Secret handling

ZeroClaw's `SecretStore` handles all credential encryption (ChaCha20-Poly1305 AEAD). Config fields with sensitive values are stored as `enc2:...` ciphertext and transparently decrypted at load time via `decrypt_optional_secret()`.

OpsClaw should use this existing infrastructure for:
- SSH key passphrases
- Telegram bot tokens
- API keys for LLM diagnosis
- Database connection strings
- Any future credential type

The separate `OpsClawSecretStore` (`secrets.enc`) may be redundant — review whether it adds value over the existing config-level encryption.

## Allowlists and blocklists

`SshCommandRunner` maintains read-only command detection (`is_read_only_command()`). Commands like `docker ps`, `systemctl status`, `df -h` are always allowed. Commands like `docker restart`, `rm`, `systemctl stop` are gated by autonomy level.

Per-target command allowlists/blocklists can override defaults in config.

## Updates

OpsClaw tracks ZeroClaw upstream. Security patches from upstream are merged promptly. The Merkle hash-chain audit trail (added in upstream v0.4.3) provides tamper-evident logging.
