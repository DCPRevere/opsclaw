# AGENTS.md

Guidelines for AI agents working in this repo.

## Vision

`OpsClaw` is a fork of `zeroclaw`. It is an agent designed to work as an SRE.

## Workspace layout

Three crates, distinct responsibilities:

- `crates/zeroclawlabs` — core agent runtime (LLM providers, channels, scheduler, memory, gateway). Do not add opsclaw-specific logic here.
- `crates/opsclaw` — autonomous SRE agent built on zeroclaw (SSH tools, k8s, incident memory, runbooks, setup wizard).
- `crates/robot-kit` — robotics/embedded toolkit. Independent of the other two.

When adding a feature, put it in the right crate. Blurring the zeroclaw/opsclaw boundary creates coupling that's hard to undo.

Default to putting it in `opsclaw` so that we can pull from the upstream in the future.

## Design rules

- Program to traits, not implementations. Extend existing abstractions (`Tool`, `Provider`, `Channel`, `Peripheral`, etc.) before inventing new ones.
- Every command that touches a remote system must go through the audit log. Do not bypass it.
- Secrets are referenced by name in config; their values live in the encrypted store. Never write a secret value into a config file or log.

## Build and test

```sh
cargo build                          # debug
cargo build --release                # size-optimized (lto=fat, stripped)
cargo build --profile release-fast   # faster local release builds
cargo test --workspace               # run all tests
```

Feature flags gate optional capabilities (Prometheus, Matrix, WhatsApp, OpenTelemetry). Check `Cargo.toml` before assuming a dependency is available.

## What not to change

- `docs/` — user-facing documentation, not auto-generated. Edit deliberately.
- The audit log format — it is hash-chained and append-only by design. Do not alter the chain structure.
- Secret encryption in `Config::save()` — all secrets must remain encrypted at rest.
