# OpenShell integration

OpenShell is an optional sandbox integration that adds policy enforcement and audit logging to OpsClaw's tool execution. When OpsClaw runs inside an OpenShell sandbox, every action is checked against a policy engine and logged to an audit endpoint before it executes.

## Detection

OpsClaw detects OpenShell automatically at startup by checking for environment variables. No configuration in `opsclaw.toml` is needed.

| Variable | Description |
|---|---|
| `OPENSHELL_ACTIVE` | Set to `1` or `true` to enable the integration |
| `OPENSHELL_SANDBOX_ID` | Unique identifier for this sandbox instance |
| `OPENSHELL_POLICY_ENDPOINT` | HTTP URL of the policy engine (e.g. `http://localhost:7070`) |
| `OPENSHELL_AUDIT_ENDPOINT` | HTTP URL of the audit log receiver (e.g. `http://localhost:7071`) |

If `OPENSHELL_ACTIVE` is absent or false, the integration is a no-op — OpsClaw behaves exactly as if OpenShell doesn't exist.

## Policy enforcement

Before executing any risky action, OpsClaw posts a policy check:

```
POST {OPENSHELL_POLICY_ENDPOINT}/api/policy
Content-Type: application/json

{
  "sandbox_id": "abc123",
  "action": "restart_deployment",
  "target": "prod/web-1",
  "details": {
    "namespace": "prod",
    "deployment": "web-1"
  }
}
```

The policy engine responds with one of:

- `{"result": "approved"}` — proceed
- `{"result": "denied", "reason": "..."}` — block the action and surface the reason
- Network error or non-200 → fail-open (action proceeds, error logged locally)

Phase 1 is fail-open: if the policy endpoint is unreachable, OpsClaw continues. A configurable fail-closed mode is planned for Phase 2.

## Audit logging

After every action (approved or denied), OpsClaw sends an audit event:

```
POST {OPENSHELL_AUDIT_ENDPOINT}/api/audit
Content-Type: application/json

{
  "timestamp": "2026-03-22T10:30:00Z",
  "sandbox_id": "abc123",
  "action": "restart_deployment",
  "target": "prod/web-1",
  "outcome": "executed",
  "details": {
    "namespace": "prod",
    "deployment": "web-1",
    "reason": "high_cpu_detected"
  }
}
```

`outcome` is one of `approved`, `denied`, or `executed`.

Audit events are also written locally to `~/.opsclaw/audit/YYYY-MM-DD.log` regardless of whether the audit endpoint is reachable.

## Local audit trail

OpsClaw maintains a local, append-only audit trail independently of OpenShell:

```bash
cat ~/.opsclaw/audit/2026-03-22.log
```

The local trail uses hash chaining — each entry includes the hash of the previous entry, making tampering detectable.
