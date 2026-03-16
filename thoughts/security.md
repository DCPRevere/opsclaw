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

Create service accounts specifically for OpsClaw, make it readonly, or prevent it from making destructive changes.

OpsClaw will warn you

## Secret handling

## Allowlists and blocklists

## Updates
