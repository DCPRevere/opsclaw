# posthog tool

Read-only PostHog queries for SRE work. Use this when an alert points at user-facing behaviour and the infra-side tools (logs, traces, metrics) don't explain it on their own.

## What it answers

- "Did this error event spike around the time the alert fired?"
- "Which feature flag was rolled out in the last 24 hours?"
- "What was *this specific user* doing when they reported the bug?"
- "Is there a session replay I can watch for them?"

## Configuration

The tool is enabled by adding a PostHog endpoint to a project's environment.

```toml
[[projects]]
name = "acme"

[[projects.environments]]
name = "prod"

[projects.environments.endpoints.posthog]
api_key = "enc2:..."          # personal API key, encrypted; supports env: / k8s: refs
project_id = "12345"          # numeric project id from PostHog
host = "https://app.posthog.com"   # default; override for EU cloud or self-hosted
```

PostHog projects rarely map 1:1 to opsclaw targets. They map closer to opsclaw projects (one PostHog project per app), sometimes per environment. Configure at the project-environment level — that's where `endpoints.posthog` lives.

The `api_key` should be a [personal API key](https://posthog.com/docs/api#authentication) with read access to events, feature flags, and session recordings.

## Actions

| Action | Required args | Use |
|---|---|---|
| `query_events` | `event_name` | Count + sample for one event in a time window. Workhorse. |
| `recent_flag_changes` | — | Flags modified in the last N hours (default 24). |
| `flag_status` | `flag_key` | One flag's full metadata: rollout %, filters, dates. |
| `events_for_user` | `distinct_id` | Last N events for one user. The "what did they do?" query. |
| `session_replay_url` | `distinct_id` | URL of the user's most recent session replay. |
| `hogql` | `query` | Escape hatch — raw HogQL/ClickHouse. |

Common optional args:

- `since` — ISO-8601 or relative (`-1h`, `-30m`). Default `-1h`.
- `until` — ISO-8601 or `now`. Default `now`.
- `limit` — max rows returned. Default 200, hard ceiling 5000.
- `filters` — for `query_events`, `{ "property": "value" }` AND-equality.

## Examples

```jsonc
// "did checkout_failed spike in the last hour?"
{ "action": "query_events", "event_name": "checkout_failed" }

// "any flag rolled out in the last 6 hours?"
{ "action": "recent_flag_changes", "hours": 6 }

// "the user reported a bug — what was their session?"
{ "action": "session_replay_url", "distinct_id": "user_abc123" }

// "show me their last events"
{ "action": "events_for_user", "distinct_id": "user_abc123", "limit": 50 }
```

## Safety

- **Read-only in v1.** No flag toggles, no event ingestion, no writes.
- **HogQL escape hatch is SELECT/WITH only.** Anything starting with `INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`/`TRUNCATE`/etc. is rejected before it reaches PostHog. Comments are stripped before the check.
- **Audited** — every call writes to the opsclaw audit log.
- **Output capped** at 16 KiB; large queries are truncated with a `[truncated]` marker.
- **Limit clamp** caps result rows at 5000 even if the agent asks for more, to keep PostHog API costs bounded.
- **`api_key` is encrypted at rest.** Plaintext values in `config.toml` are encrypted on the next `cfg.save()` (the wizard saves after every change). Resolve via `enc2:` / `env:` / `k8s:` references for live deployments.

## Doctor

`opsclaw doctor` probes each configured PostHog endpoint with an authenticated `GET /feature_flags`. Surfaces three failure modes distinctly:

- `401 Unauthorized` — the api_key is wrong.
- `404 Not Found` — the project_id doesn't exist on this host.
- transport error — the host is unreachable.

## Escalation handoff

When the agent calls `opsclaw_notify`, it can include a `links` array. PostHog session replay URLs are the canonical use case: agent looks up `session_replay_url` for the affected user, then passes the URL to `opsclaw_notify` as a link. Human triages from the replay in the alert payload.

## Roadmap

v2 candidates, when there's a real use case:

- **Webhook ingress** — let PostHog alerts/flag-change events POST to opsclaw's gateway, kick off an agent run with the alert as starting context. The biggest v2 lift; needs gateway routing.
- **Funnel queries** — by funnel id.
- **`correlate`** — composite "in this time window, here's what flags changed and which events spiked," so the agent doesn't have to compose three calls itself.
- **Write actions** — kill a flag, after autonomy gating. High blast radius; needs careful design.
- **CLI wizard step** — `opsclaw config target add` doesn't yet offer to configure PostHog. For now, hand-edit `config.toml` after the wizard exits.
- **Live test against PostHog** — every action is wiremock-backed; the first real-API call may surface a field-mapping issue worth fixing.
