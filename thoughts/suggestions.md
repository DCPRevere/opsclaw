# Suggestions

Ideas worth exploring. Not committed to the roadmap yet.

## New Relic SRE Agent comparison (Mar 2026)

New Relic launched an "SRE Agent" with four pillars:
1. Autonomous Investigation — retry queries, analyse service dependencies, isolate root causes
2. Context Intelligence — index runbooks and past incidents with persistent memory; share findings across Slack/Jira
3. Active Remediation — runbook execution with human confirmation and governance guardrails
4. Agent Orchestration — coordinate specialist agents via a runtime orchestration engine

**How OpsClaw compares:**

| NR capability | OpsClaw equivalent | Status |
|---|---|---|
| Autonomous investigation | MonitoringAgent + LLM diagnosis loop | ✅ Phase 3 |
| Context intelligence (runbooks + incidents) | Incident memory search + runbook engine | ✅ Phase 3 |
| Active remediation (human confirm) | Autonomy approve mode + inline buttons | ✅ Phase 3 |
| Agent orchestration | ZeroClaw multi-agent upstream | ✅ upstream |
| Jira/PagerDuty integration | Not yet | ❌ |
| Correlated telemetry (metrics+logs+traces+deploys) | Phase 4 data sources | 🔨 Phase 4 |

**Key NR advantage:** NR runs against a full observability platform — metrics, logs, traces, and deployment events all correlated. OpsClaw is currently polling-based; Phase 4 data sources close this gap by querying existing telemetry backends.

**Key OpsClaw advantage:** NR SRE Agent requires NR's platform. OpsClaw is self-hosted, provider-agnostic, works with whatever infrastructure already exists.

## Data sources: pull-based, not push-based (Mar 2026)

Core design constraint: OpsClaw fits into existing infrastructure without requiring changes. Specifically:

- No OTLP receiver — services should not push to OpsClaw. Query existing Jaeger/Grafana/Prometheus instead.
- No CI/CD webhooks — poll GitHub/GitLab APIs instead.
- No agents on targets — SSH + Docker API + existing log stores.

The value proposition is: give OpsClaw an API token, and it gains a new signal. Nothing else changes.

First priority data sources for Sacra:
1. **Seq** — error logs via Events API (already running, API key known)
2. **Jaeger** — traces for the affected service (already running, no auth required)
3. **Docker inspect** — deploy timestamp detection (zero config, uses existing SSH)
4. **GitHub** — release/deployment history (needs PAT)

## Prometheus / Grafana pull (Mar 2026)

OTEL supports a Prometheus exporter — services expose `/metrics` and Prometheus scrapes it. This is the one legitimate "pull" pattern in the OTEL ecosystem. If users have Prometheus already, OpsClaw could query it via PromQL (`/api/v1/query_range`) as a data source with no changes to the monitored services.

For users with Grafana, the Grafana HTTP API exposes the same PromQL queries plus dashboard data.

## Jira / PagerDuty integration (future)

NR explicitly integrates with Jira and incident workflows. This unlocks the enterprise tier. Suggested approach: when escalation fires, OpsClaw can optionally create a Jira issue or PagerDuty incident with the full diagnosis context attached. Zero-config if the user has neither — just an additional data source config block.

## Deployment event correlation via git log (future)

Zero-config alternative to GitHub API: if OpsClaw can SSH into the server and run `git -C /path/to/app log --oneline -20`, it gets recent commit history for whatever is actually deployed. Doesn't need GitHub access or CI integration. Works for any git-deployed service.

Could combine with `docker inspect` to triangulate: "image was updated at 02:05, the last commit before that timestamp was abc123 (message: 'fix: batch job memory limit')" — without any CI system involved.

## Rust contribution barrier

Most SRE/DevOps engineers know Python or Go, not Rust. This may limit community contributions. Options:
- Provide a Python SDK for custom data sources or runbooks
- Support WASM plugins (longer term)
- Focus on config-driven extensibility (new data sources via config, not code)

Not urgent while OpsClaw is pre-launch, but worth considering before open-sourcing.
