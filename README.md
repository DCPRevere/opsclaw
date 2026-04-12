<h1 align="center">OpsClaw — Autonomous SRE Agent</h1>

<p align="center">
  <strong>Monitors your servers and fixes them while you sleep.</strong><br>
  Built on <a href="https://github.com/zeroclaw-labs/zeroclaw">ZeroClaw</a>. 100% Rust. Single binary.
</p>

<p align="center">
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-edition%202021-orange?logo=rust" alt="Rust Edition 2021" /></a>

  <a href="https://github.com/dcprevere/opsclaw/releases/latest"><img src="https://img.shields.io/badge/version-v0.6.2-blue" alt="Version v0.6.2" /></a>
</p>

OpsClaw is an autonomous SRE agent that SSHes into your servers, inspects Kubernetes clusters, runs diagnostics, remembers past incidents, and follows your runbooks — all without waking you up. It uses the [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) runtime for LLM providers, channels, scheduling, and memory, and adds SRE-specific tooling on top.

## Highlights

- **SSH access** — connects to hosts via `russh`, runs commands, tails logs, and applies fixes.
- **Kubernetes native** — inspects pods, deployments, services, and events via the `kube` crate.
- **Incident memory** — remembers what broke, what fixed it, and how to prevent it next time.
- **Runbooks** — codified SOPs that the agent follows when it detects known failure modes.
- **Setup wizard** — guided onboarding to configure targets, credentials, and alerting.
- **Single binary** — small Rust binary, fast startup, low memory footprint. Runs on a $10 board.
- **Multi-channel alerts** — reports to Slack, Discord, Telegram, Email, or any ZeroClaw channel.
- **Autonomy levels** — ReadOnly (observe only), Supervised (act with approval), Full (autonomous within policy).

## Quick start

```bash
# Clone and build
git clone https://github.com/dcprevere/opsclaw.git
cd opsclaw
cargo build --release --locked

# Run the setup wizard
cargo run --release -- onboard

# Start the agent
cargo run --release -- daemon
```

### From a release binary

```bash
# Install and onboard
./install.sh
opsclaw onboard
opsclaw daemon
```

## Architecture

OpsClaw is a workspace of three crates:

| Crate | Purpose |
|-------|---------|
| `crates/zeroclawlabs` | Core agent runtime (LLM providers, channels, scheduler, memory, gateway). Upstream ZeroClaw. |
| `crates/opsclaw` | Autonomous SRE agent (SSH tools, k8s, incident memory, runbooks, setup wizard). |
| `crates/robot-kit` | Robotics/embedded toolkit. Independent of the other two. |

## Configuration

Minimal `~/.zeroclaw/config.toml`:

```toml
default_provider = "anthropic"
api_key = "sk-ant-..."
```

OpsClaw inherits ZeroClaw's full configuration system. See the upstream [config reference](docs/reference/api/config-reference.md) for all options.

### SSH targets

Configure hosts the agent can reach in your workspace config or via the setup wizard (`opsclaw onboard`).

### Kubernetes

OpsClaw uses your local kubeconfig by default. No extra configuration needed if `kubectl` already works.

## CLI commands

```bash
# Setup and status
opsclaw onboard              # Guided setup wizard
opsclaw status               # Show daemon/agent status
opsclaw doctor               # Run system diagnostics

# Gateway + daemon
opsclaw gateway              # Start gateway server
opsclaw daemon               # Start full autonomous runtime

# Agent
opsclaw agent                # Interactive chat mode
opsclaw agent -m "message"   # Single message mode

# Memory
opsclaw memory list          # List memory entries (including incidents)
opsclaw memory stats         # Memory statistics
```

## Autonomy levels

| Level | Behavior |
|-------|----------|
| `ReadOnly` | Agent can observe but not act |
| `Supervised` (default) | Agent acts with approval for medium/high risk operations |
| `Full` | Agent acts autonomously within policy bounds |

## Security

OpsClaw connects to real infrastructure. Treat it seriously.

- **Sandboxing** — workspace isolation, path traversal blocking, command allowlists, forbidden paths.
- **Approval gating** — interactive approval for medium/high risk operations in Supervised mode.
- **Audit log** — every command that touches a remote system is logged. The log is hash-chained and append-only.
- **Secrets** — referenced by name in config; values live in the encrypted store. Never written to config files or logs.
- **E-stop** — emergency shutdown capability.

See [SECURITY.md](SECURITY.md) for the full security policy.

## Build and test

```bash
cargo build                          # debug
cargo build --release                # size-optimized (lto=fat, stripped)
cargo build --profile release-fast   # faster local release builds
cargo test --workspace               # run all tests
```

Feature flags gate optional capabilities. Check `Cargo.toml` before assuming a dependency is available.

## Upstream

OpsClaw is a fork of [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw). The `crates/zeroclawlabs` crate tracks upstream. SRE-specific logic lives in `crates/opsclaw` to keep the boundary clean and make future upstream pulls straightforward.

## License

All rights reserved.
