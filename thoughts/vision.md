# Vision

## What OpsClaw is

OpsClaw is the first engineer who never sleeps, never forgets, and never gets paged at 3am wishing they'd chosen a different career.

It SSHes into your servers. It reads your logs. It watches your containers. It understands your stack — not because someone wrote a plugin for your specific setup, but because a language model can read a Dockerfile and understand what it means when postgres stops accepting connections.

When something breaks at 2am, OpsClaw is already looking at it. It's already checked the logs, already compared against the baseline, already found the last three times this happened and what fixed it. By the time you wake up, there's a message on your phone: "sacra-api crashed at 02:17 — OOM from the batch job. Restarted it. Increased memory limit. Here's what I found in the logs."

That's not monitoring. That's an engineer.

## Why this matters

Every company with software in production has the same problem: someone has to watch it. Someone has to be on call. Someone has to know what "normal" looks like so they can spot "abnormal."

Small teams can't afford that person. They do it themselves, badly, and their production systems are held together with hope and cron jobs.

Big teams can afford it, but the knowledge lives in people's heads. When your senior SRE leaves, they take six months of tribal knowledge with them. The runbooks in Confluence haven't been updated since 2023.

OpsClaw solves both problems:

**For small teams**: you get a DevOps engineer you couldn't otherwise afford. Not a dashboard — an engineer. One that actually SSHes in and fixes things.

**For big teams**: you get institutional memory that doesn't quit. Every incident diagnosed, every fix applied, every pattern learned — it's all there, searchable, growing. Your L1 on-call becomes redundant. Your L2 engineers get paged with full context instead of a raw alert.

## What makes this different

The monitoring space is crowded. Datadog, Grafana, PagerDuty, OpsGenie — they all do the same thing differently. They show you graphs. They send you alerts. Then you SSH in and figure it out yourself.

OpsClaw doesn't show you graphs. **OpsClaw is the person who looks at the graphs, understands them, and acts.** It's the difference between a fire alarm and a firefighter.

Other "AI ops" tools correlate alerts or summarise logs. They help you find the problem faster. OpsClaw finds the problem, diagnoses it, fixes it if it can, and escalates with perfect context if it can't.

## How it works

One binary. Point it at your server. It figures out what's running.

```
opsclaw setup
```

That's the entire onboarding. It discovers your Docker containers, your systemd services, your listening ports, your Kubernetes pods. It builds a picture of your stack. You tell it the things it can't infer — "Redis is for sessions only, don't restart it lightly" — and it remembers.

Then it watches. Every few minutes, it checks. When something changes — a container dies, disk fills up, a deployment degrades — it kicks in:

1. **Detect**: health check diff, baseline anomaly, log error, probe failure
2. **Remember**: "have I seen this before?" Search incident memory.
3. **Diagnose**: feed everything to the LLM — current state, baseline, logs, past incidents, target context
4. **Act**: execute the runbook, restart the container, scale the replicas — or propose the fix and wait for approval
5. **Learn**: record what happened, what worked, update the runbook

The cycle repeats. OpsClaw gets better at your infrastructure over time. It builds institutional knowledge that persists across team changes, across incidents, across years.

## The trust spectrum

Nobody should hand an AI the keys to production on day one. OpsClaw earns trust:

- **Dry run**: watch and record. "Here's what I would have done." Run this for a week. Read the log. See if it's right.
- **Approve**: propose actions, wait for your OK. Run this for a month. Build confidence.
- **Auto**: fix it. You trust OpsClaw. It's earned it.

Every action is logged. The audit trail is append-only and tamper-evident. If OpsClaw ever does something wrong, there's a complete, honest record of what happened and why.

## The end state

OpsClaw running on your infrastructure should feel like having a quiet, competent SRE who's always watching, always learning, always ready. Not flashy. Not noisy. Just... there. Doing the work that keeps everything running.

The 3am page goes to OpsClaw first. Most of the time, it handles it. When it can't, it wakes you up with everything you need to know — what happened, what it tried, what it thinks you should do.

That's worth more than a dashboard. That's worth more than an alerting pipeline. That's a colleague.
