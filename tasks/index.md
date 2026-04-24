# Tasks

Priority: **P0** critical, **P1** high, **P2** medium, **P3** low

## Immediate

- [ ] **P0** [Write `opsclaw.toml` for Sacra](sacra-config.md) — blocks first real-world deployment
- [ ] **P0** [Integration test against Sacra](sacra-integration-test.md) — proves the product works end-to-end

## Features

- [x] **P1** [`opsclaw postmortem` CLI command](postmortem-cli.md) — merged 06043db5
- [x] **P1** [Setup wizard: more notification channels](setup-wizard-notifications.md) — merged 2d5f794f
- [x] **P1** [Doctor: check data source connectivity](doctor-data-sources.md) — merged 0d1e2ddb
- [x] **P2** [Setup wizard: data source endpoints](setup-wizard-data-sources.md) — merged 83f096ed
- [x] **P2** [SkillForge not reachable from CLI](skillforge-cli.md) — merged 653d2ced
- [x] **P3** [ClawHub and HuggingFace scout sources are stubs](clawhub-huggingface-scouts.md) — merged 42472856
- [x] **P3** [OpenShell integration](openshell-integration.md) — merged 544351a9

## Bugs / Hardening

- [x] [Runbook executor bare `.unwrap()`](runbook-unwrap.md) — merged 6bc8e2d8
- [x] [Digest command silently drops errors](digest-silent-errors.md) — merged 6bc8e2d8
- [x] [Daemon doesn't restart failed monitor tasks](daemon-restart-failed-tasks.md) — merged 99bbe826

## Tests

- [ ] **P1** [`ops_cli.rs` has zero test coverage](test-ops-cli.md) — 13 untested handlers, highest regression risk
- [x] **P2** [`ops/context.rs` has no tests](test-context.md) — merged cef9cf5a
- [ ] **P2** [`ops/daemon.rs` has no tests](test-daemon.md) — long-running process, hard to debug without tests

## Future

- [ ] **P2** [Self-authoring runbooks](self-authoring-runbooks.md) — LLM drafts runbooks from incident timelines + audit trail
- [ ] **P2** [Predictive alerting](predictive-alerting.md) — extend baseline trends beyond disk; multi-week history, forward projections
- [ ] **P3** [Compliance report generation](compliance-reports.md) — SOC 2-style reports from existing audit trail
- [ ] **P3** [Cost-aware operations](cost-aware-ops.md) — cloud billing APIs, idle resource detection, right-sizing suggestions
- [ ] **P3** [Deeper discovery](deeper-discovery.md) — Dockerfile parsing, framework detection, dependency graph from network connections

## Upstream

