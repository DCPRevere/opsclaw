# Projects, Environments, and Targets

OpsClaw organises what it manages into three levels.

```
Project            product or service line
 └── Environment   policy boundary (dev, staging, prod)
      └── Target   one addressable endpoint
```

One OpsClaw instance can manage many Projects. Each Project can have many Environments. Each Environment can have many Targets.

Status: Target is implemented today (see [targets.md](targets.md)). Project and Environment are the target state of the model; a flat `[[targets]]` list deserialises as "one implicit Project, one implicit Environment."

## Why three levels

Flat target lists answer "where do I act?" but not "under what policy?" or "in what product context?". The hierarchy separates three concerns that collide in a flat list:

- **Project** — what the agent is reasoning about (product, runbooks, context).
- **Environment** — what it is allowed to do (autonomy, escalation, shared endpoint pools).
- **Target** — how it connects (credentials, address, connection type).

Keeping them separate means prod and dev can share everything above the Environment line and diverge cleanly below it.

## Invariants

1. One Target = one credential set = one audit identity.
2. Environment is policy; Target is connection. Do not mix.
3. Secrets never sit in cleartext at rest.
4. Config declares endpoints; runtime discovers everything else (pods, processes, services).

## Inheritance

Autonomy, escalation, and notification routing flow down the tree. A Target inherits its Environment's autonomy unless it overrides. An Environment inherits its Project's context files and prepends its own.

Credentials do not inherit. Each Target holds its own secrets. If two Targets share a key, they reference the same named secret — they do not share a field.

## Addressing

Tools and CLI commands address a Target by `project/environment/target`, with sensible fallbacks when the path is unambiguous:

```
opsclaw ssh shopfront/prod/web-1 "systemctl status nginx"
opsclaw ssh prod/web-1              # if only one project
opsclaw ssh web-1                   # if only one project and one environment
```

The audit log always records the fully qualified path.

## See also

- [projects.md](projects.md) — the Project level
- [environments.md](environments.md) — the Environment level
- [targets.md](targets.md) — the Target level
- [config.md](config.md) — the on-disk schema
- [autonomy.md](autonomy.md) — how autonomy is resolved
