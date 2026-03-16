# Memory

How OpsClaw remembers things about the systems it manages.

## What gets remembered

- **Config** — targets, namespaces, autonomy levels, notification channels, polling intervals. Declarative, user-editable.
- **Target snapshot** — discovery scan results. What's running, when it was last scanned. Updated on rescan, used to detect drift.
- **Target context** — user-provided freeform notes about their setup. Loaded into the model's context when working on that target. Things the scan can't infer: naming conventions, what services are for, non-default ports, "don't panic if X."
- **Secret store** — credentials referenced by name, never logged or exposed.
- **Audit log** — append-only record of every action taken.
- **Incident memory** — things OpsClaw learns from operating. "Last time the worker restarted repeatedly, it was an OOM from a batch job at 02:00." Builds up over time, makes diagnosis faster.

OpsClaw maintains notes for each element of your setup.

```
audit/2026-03-16.txt
daily/2026-03-16.md
infra/postgres.md
incidents/2026-03-16-000.md
SOUL.md
MEMORY.md
```

## Context vs memory

Target context is what the user tells OpsClaw upfront. Incident memory is what OpsClaw learns by doing. Both feed into diagnosis, but context is static (until the user updates it) and memory grows with experience.

## Open questions

- How long should incident memory persist? Forever? Decay after N months?
- Should OpsClaw surface what it remembers? "I've seen this before — last time it was X."
- Can the user review and prune memories? "Forget that, it's no longer relevant."
- How to avoid stale memories causing bad diagnoses? A fix that worked 6 months ago might be wrong today.
