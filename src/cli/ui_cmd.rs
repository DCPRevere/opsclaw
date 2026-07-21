//! `opsclaw-cli ui` (DESIGN.md §4: "`opsclaw ui` opens tunnel + browser").
//!
//! Small and honest, per the task brief: this is a thin wrapper around
//! `xdg-open`/`open`/`start` (no `open`/`webbrowser` crate — `Cargo.toml` is
//! the merge-conflict hotspot for parallel worktree agents, same reasoning
//! `cli::prompt`'s doc gives for not adding a prompt crate; a three-way
//! `std::process::Command` dispatch is gianna's own precedent, ported
//! verbatim from `bin/cli/remote/mod.rs::open_browser`) plus, with
//! `--tunnel`, an SSH port-forward spawned as a child process and left
//! running until the operator kills it (Ctrl-C) — there is no in-process
//! tunnel management, health check, or auto-reconnect. If the daemon isn't
//! actually reachable at the far end, or the SSH command isn't on `PATH`,
//! or the local port is already taken, this command fails exactly the way
//! running that `ssh`/`xdg-open` command by hand would — no attempt is made
//! to paper over any of that with retries or a nicer error, because a nicer
//! error here would have to guess at failures this module has no way to
//! actually diagnose (is `sshd` down on the far end? is the key wrong? is
//! the local port held by an unrelated process?).
//!
//! ## Limitations (documented, not hidden)
//!
//! - No tunnel lifecycle management: the spawned `ssh -N -L` child is
//!   handed nothing beyond stdout/stderr inheritance; this process blocks
//!   on it (so Ctrl-C here kills the tunnel too), but there's no retry, no
//!   liveness probe, and no attempt to detect a half-dead tunnel.
//! - No verification that the gateway (or, with `--tunnel`, the daemon at
//!   the far end) is actually listening — `ui` opens a browser at a URL; if
//!   nothing answers, the browser shows its own connection-refused page,
//!   same as typing the URL by hand.
//! - `--tunnel user@host[:port]` assumes an `ssh` binary on `PATH` with
//!   working key-based auth already set up (matching the target's ssh
//!   executor's own assumption, `targets/`'s doc) — this command does not
//!   manage keys, known_hosts, or jump-host chaining itself (though the
//!   underlying `ssh` invocation honours the operator's own `~/.ssh/config`
//!   for that, including any `ProxyJump`).

use std::path::Path;

use crate::Result;
use crate::cli::remote::session;

/// Best-effort browser open via the platform's native "open a URL" command.
/// Returns `Ok(())` only if the command was successfully SPAWNED — this
/// says nothing about whether a browser actually appeared (headless boxes,
/// a broken `$BROWSER`, ...), matching gianna's own `open_browser`'s
/// honesty (`bin/cli/remote/mod.rs`: "-> bool" there; here it becomes a
/// `Result` so `ui`'s caller can report the failure instead of silently
/// swallowing it, but the underlying guarantee is identical: spawn success,
/// not "and a window appeared").
pub fn open_url(url: &str) -> Result<()> {
    // `$BROWSER` first (an explicit operator override — common on servers/
    // WSL/remote boxes where the platform default would be wrong or absent),
    // then the platform default.
    let mut cmd = if let Some(browser) = std::env::var_os("BROWSER").filter(|b| !b.is_empty()) {
        let mut c = std::process::Command::new(browser);
        c.arg(url);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else if cfg!(windows) {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| crate::Error::other(format!("could not open a browser: {e}")))?;
    Ok(())
}

/// Parse `user@host[:port]` into `(ssh_target, port)`. `ssh_target` is
/// handed to the `ssh` binary verbatim (`user@host`, letting `ssh` itself
/// validate it and honour `~/.ssh/config`); `port` defaults to 22.
fn parse_tunnel_host(spec: &str) -> (String, u16) {
    match spec.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            (host.to_string(), port.parse().unwrap_or(22))
        }
        _ => (spec.to_string(), 22),
    }
}

/// Spawn `ssh -N -L <local_port>:127.0.0.1:<daemon_port> <ssh_target> -p
/// <ssh_port>` and block until it exits (Ctrl-C tears down both the tunnel
/// and this command — there is no daemonizing). `local_port` is chosen by
/// the OS (bind to port 0, read it back, then hand that exact number to
/// `ssh`) so two concurrent `ui --tunnel` invocations never collide.
async fn spawn_tunnel(tunnel_spec: &str, daemon_port: u16) -> Result<(std::process::Child, u16)> {
    let (ssh_target, ssh_port) = parse_tunnel_host(tunnel_spec);
    // Reserve a local port by binding it, then immediately drop the
    // listener so `ssh` can bind it instead — a small TOCTOU window (another
    // process could grab it between drop and ssh's own bind) that matches
    // every "find a free port" trick's inherent limitation; ssh's own error
    // on a lost race is clear enough not to paper over.
    let probe = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| crate::Error::other(format!("could not reserve a local port: {e}")))?;
    let local_port = probe.local_addr().map_err(|e| crate::Error::other(e.to_string()))?.port();
    drop(probe);

    let child = std::process::Command::new("ssh")
        .args([
            "-N",
            "-L",
            &format!("{local_port}:127.0.0.1:{daemon_port}"),
            &ssh_target,
            "-p",
            &ssh_port.to_string(),
        ])
        .spawn()
        .map_err(|e| crate::Error::other(format!("could not spawn ssh: {e}")))?;
    Ok((child, local_port))
}

#[derive(Debug, Default)]
pub struct UiOutcome {
    pub url: String,
    pub tunnel_spawned: bool,
}

/// `opsclaw-cli ui [--tunnel user@host[:port]]`: figure out the URL to
/// open, optionally standing up an SSH tunnel first, then open a browser at
/// it. URL resolution, in order:
/// 1. A remote session (`cli::remote::session::load()`) — the configured
///    gateway's own `server` URL.
/// 2. `--tunnel`: `http://127.0.0.1:<local_port>` (the tunnel just opened),
///    `daemon_port` taken from `cfg_path`'s `daemon.listen` (falling back to
///    the config default when unset/unparseable — `ui` opening the wrong
///    port is a much smaller failure than `ui` refusing to run at all).
/// 3. Local config's own `daemon.listen`, as `http://127.0.0.1:<port>` —
///    the box this CLI runs on IS the daemon (DESIGN §4's plain case: no
///    tunnel needed because operator and daemon share a host).
pub async fn run(cfg_path: &Path, tunnel: Option<&str>) -> Result<UiOutcome> {
    if let Some(spec) = tunnel {
        let daemon_port = local_daemon_port(cfg_path);
        let (mut child, local_port) = spawn_tunnel(spec, daemon_port).await?;
        let url = format!("http://127.0.0.1:{local_port}");
        // Give ssh a brief moment to establish before pointing a browser at
        // it — best-effort, not a readiness probe (module doc: no liveness
        // checking here).
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        open_url(&url)?;
        println!("Tunnel to {spec} up on {url} — Ctrl-C to tear it down.");
        let _ = child.wait();
        return Ok(UiOutcome { url, tunnel_spawned: true });
    }

    if let Some(session) = session::load() {
        open_url(&session.server)?;
        return Ok(UiOutcome { url: session.server, tunnel_spawned: false });
    }

    let port = local_daemon_port(cfg_path);
    let url = format!("http://127.0.0.1:{port}");
    open_url(&url)?;
    Ok(UiOutcome { url, tunnel_spawned: false })
}

/// The port this box's own daemon would bind (`daemon.listen`, "host:port"),
/// or the config's documented default if unset/unparseable/no config file
/// exists yet — never fails `ui` outright over a config detail it can
/// reasonably default around.
fn local_daemon_port(cfg_path: &Path) -> u16 {
    // Matches `config::DaemonCfg::default()`'s own `listen` value.
    const DEFAULT_PORT: u16 = 8484;
    crate::config::Config::load(Some(cfg_path))
        .ok()
        .and_then(|c| c.daemon.listen.rsplit_once(':').map(|(_, p)| p.to_string()))
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tunnel_host_splits_host_and_port() {
        assert_eq!(
            parse_tunnel_host("op@bastion.example.com:2222"),
            ("op@bastion.example.com".into(), 2222)
        );
    }

    #[test]
    fn parse_tunnel_host_defaults_to_22() {
        assert_eq!(
            parse_tunnel_host("op@bastion.example.com"),
            ("op@bastion.example.com".into(), 22)
        );
    }

    #[test]
    fn parse_tunnel_host_treats_non_numeric_suffix_as_part_of_the_host() {
        // e.g. an IPv6-ish or oddly-named host with a literal colon that
        // isn't a port — falls back to the whole spec at the default port
        // rather than mis-splitting.
        assert_eq!(parse_tunnel_host("op@host:notaport"), ("op@host:notaport".into(), 22));
    }

    #[test]
    fn local_daemon_port_defaults_when_no_config_exists() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        assert_eq!(local_daemon_port(&cfg_path), 8484);
    }

    #[test]
    fn local_daemon_port_reads_configured_listen() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        std::fs::write(&cfg_path, "[daemon]\nlisten = \"0.0.0.0:9999\"\n").unwrap();
        assert_eq!(local_daemon_port(&cfg_path), 9999);
    }
}
