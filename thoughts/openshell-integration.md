# NVIDIA OpenShell — Optional Integration for OpsClaw

**Source**: https://developer.nvidia.com/blog/run-autonomous-self-evolving-agents-more-safely-with-nvidia-openshell/
**Date**: 2026-03-19

## What OpenShell Is

NVIDIA OpenShell is an open-source (Apache 2.0) runtime that sits *between* an agent and its infrastructure. Core idea: **out-of-process policy enforcement** — constraints on what the agent can do are enforced by the runtime, not by the agent itself. Even a compromised agent can't override them.

Three components:
1. **Sandbox** — isolated execution environment designed for long-running, self-evolving agents. Not generic container isolation. Handles skill development/verification, programmable system/network isolation. Policy updates happen live with full audit trail.
2. **Policy engine** — enforces constraints at filesystem, network, and process layers. Evaluates every action at binary/destination/method/path level. Agent can propose policy updates; human has final approval.
3. **Privacy router** — routes inference to local open models (keeps sensitive context on-device) vs frontier models based on *your* policy, not the agent's.

Key command: `openshell sandbox create --remote spark --from openclaw` — zero code changes needed. Any agent (OpenClaw, Claude Code, Codex) runs unmodified inside OpenShell.

## Why This Matters for OpsClaw

OpsClaw is an autonomous SRE agent that runs commands on production infrastructure. It's *exactly* the threat model OpenShell is designed for: persistent shell access, live credentials, ability to rewrite its own tooling, hours of accumulated context against internal APIs.

Currently OpsClaw has its own autonomy levels (notify → suggest → auto-fix) and a remediation approval flow. But these are **in-process** — the agent polices itself. OpenShell moves the control plane outside the agent.

## Integration Approach: Optional, Not Required

OpenShell should be an **optional runtime** for OpsClaw, not a dependency:

- **Without OpenShell**: OpsClaw runs as today — SSH-based, autonomy config in TOML, trust-the-operator model. Fine for homelab, small-scale, single-user.
- **With OpenShell**: OpsClaw runs inside an OpenShell sandbox. Policy engine governs which remediation commands it can execute. Privacy router decides whether diagnostic data hits frontier APIs or stays local. Enterprise-grade audit trail.

### Detection & Adaptation
OpsClaw should detect at startup whether it's running inside an OpenShell sandbox (env var? socket? API endpoint?) and adapt:
- If inside OpenShell: defer to its policy engine for command approval instead of internal autonomy levels. Log actions to OpenShell's audit trail. Respect its network isolation rules.
- If outside: use existing autonomy config as-is.

### Concrete Benefits
- **Remediation sandboxing**: OpsClaw proposes `systemctl restart nginx` → OpenShell policy engine checks if that's allowed for this target → approved/denied at runtime level, not agent level.
- **Credential isolation**: SSH keys, API tokens stay in OpenShell's controlled environment. Agent can use them but can't exfiltrate them even if prompt-injected via malicious log content.
- **Privacy routing**: Diagnostic logs containing PII/secrets → routed to local model for analysis. Only sanitised summaries hit Claude/GPT.
- **Multi-target governance**: Different policies per target (prod stricter than staging).

### Implementation Priority
- **Phase 6 or later** — not urgent. Focus on core SRE loop first.
- Start with: detect OpenShell → log to its audit trail → respect its command allow/deny.
- Later: full policy engine integration for remediation approval.

## Key Quote

> "A stateless chatbot has no meaningful attack surface. An agent with persistent shell access, live credentials, the ability to rewrite its own tooling, and six hours of accumulated context running against your internal APIs is a fundamentally different threat model."

This is OpsClaw's exact use case. OpenShell is building the trust infrastructure we'd otherwise have to build ourselves.
