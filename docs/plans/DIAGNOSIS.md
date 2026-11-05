# Diagnosis features to borrow

Status: proposal. Sources: Datadog Bits AI SRE, Traversal, Resolve.ai,
HolmesGPT, Causely (November 2026 survey). Vendor accuracy claims are
unverified; the ranking below follows the strength of public evidence, not
marketing.

## Current OpsClaw baseline

- Persona prompt asks for corroboration and a hypothesis (`src/agent/prompt.rs`).
- A hypothesis is a single free-text string on approvals and incidents.
- No service dependency model, no change feed, no metric baselines.
- Evals (`tests/evals.rs`) test safety behaviour, not diagnostic accuracy.

## Ranked proposals

### 1. Diagnosis eval harness — from every serious vendor

You cannot improve what you do not score.

- Replay real past incidents as frozen telemetry fixtures: tool outputs
  recorded, served back deterministically. Extend `sim/` and `k3d/` with
  multi-service causal scenarios (upstream dependency down, bad deploy).
- Score: correct root cause named (exact / partial / wrong), steps, tokens,
  wall time. Penalize extra blamed components (ITBench-AA does this).
- Run HolmesGPT on the same fixtures as an external baseline.

### 2. Dependency / topology graph — Causely, Traversal

The intervention with the strongest evidence (Causely: root-cause diagnosis
75% → 100% once agents were given causal access).

- Per project environment: services, what each calls, what backs it
  (DB, queue, ES index, EventStore stream), which target runs it.
- Seed from config and declared Resources; enrich by discovery
  (k8s Services/Ingress, env vars, connection strings, Prometheus labels)
  and accept operator corrections.
- Tool: `topology(service)` → upstreams, downstreams, shared resources.
- Diagnosis rule: walk upstream from the symptom before blaming the symptom.

### 3. Change correlation — Bits, Traversal, Grafana Sift

"What changed?" answers most incidents.

- One change timeline per environment: ArgoCD syncs, image tag changes,
  k8s rollouts, config edits, systemd restarts, package upgrades, cert
  renewals, OpsClaw's own actions (from the audit chain).
- Tool: `recent_changes(scope, window)`; auto-attached to every new incident.

### 4. Hypothesis tree — Bits AI SRE

Datadog's documented failure: the right cause was found by one tool call and
then lost during summarization. Their fix was explicit, recursive hypotheses.

- Replace the single hypothesis string with a structured list:
  `{claim, status: open|supported|refuted, evidence: [tool-call ids]}`.
- The agent must mark each hypothesis supported or refuted before concluding.
- Postmortems and approvals render the tree, not just the winner.

### 5. Evidence-linked findings — Cleric, Traversal, HolmesGPT

- Every claim in a diagnosis cites the audit-chain entry (tool call) that
  supports it. Uncited claims are flagged in the UI.
- Already cheap for OpsClaw: the audit chain exists.

### 6. Baselines and anomaly checks — Sift, Bits

- Store per-target normal ranges (CPU, memory, disk growth, error rate,
  queue depth, restart count) from scheduled scans.
- Deterministic detectors run first ("errors up 40x vs 7-day baseline",
  "new log pattern since 14:02"); the LLM reasons over their output instead
  of raw dumps. Cheaper and less hallucination-prone.

### 7. Learn from resolved incidents — Bits, Resolve.ai

- On resolution, store a compact record in Hindsight: symptom signature →
  confirmed root cause → evidence that discriminated it.
- On a new incident, recall similar past ones and test their causes first.
- Wire operator feedback ("root cause was wrong, it was X") into that record.

## Not worth taking now

- Autonomous remediation features (Resolve.ai's focus): out of scope.
- Proprietary telemetry pipelines (Bits): OpsClaw stays a client of existing
  Prometheus / Elasticsearch / Loki.

## Suggested order

1 → 3 → 4 → 2 → 5 → 6 → 7. Eval first so each later change is measured.
Change correlation and the hypothesis tree are small and high-yield; the
topology graph is the biggest lever but the most work.
