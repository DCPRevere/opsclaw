//! `opsclaw-cli chat` — the LOCAL chat REPL (DESIGN.md §1: "chat REPL" in
//! the local command list), used when no remote gateway is configured
//! (`cli::remote::session::load()` finds nothing — see `bin/cli/main.rs`'s
//! dispatch, which picks this path vs. `cli::remote::chat` accordingly).
//!
//! This boots the SAME library wiring the daemon uses
//! (`boot::daemon_state` — exactly what `Command::Daemon` in
//! `bin/cli/main.rs` calls) but never binds HTTP: no `server::run`, no
//! listener, no scheduler tick, no inbound-channel consumer. It drives
//! `state.chat.chat(...)` directly in a blocking readline loop — the same
//! seam the gateway's chat route and the Telegram inbound loop drive
//! (`channels::ChatHandler`'s own doc: "any surface — a channel's inbound
//! loop, the gateway's chat route, or the CLI REPL").
//!
//! ## Principal: `Principal::System`
//!
//! There is no authenticated account in local mode — no login, no session,
//! nothing to attribute a human identity to (unlike the gateway's chat
//! route, which resolves an `Authed` account, or the remote CLI, which
//! carries the token's account). Of the three `Principal` variants
//! (`Agent`, `Operator`, `System`), `Operator { account }` is the wrong
//! choice: it would require fabricating an `accounts` row id that this
//! process never authenticated, which is exactly the kind of "trusted
//! positional context" `ChatHandler`'s doc warns must never be invented.
//! `Principal::System` is the honest one: it already means "the daemon
//! itself (housekeeping, doctor)" (`domain::Principal`'s doc), and a local
//! operator sitting at the same keyboard the daemon would otherwise run
//! unattended on is the same trust level — physical access to the box. The
//! audit trail and any policy/approval decisions this turn triggers will
//! show `system` as the requester, not a named human; documented here so
//! that's a deliberate, legible choice rather than a silent default.
//!
//! `speaker` (attribution label for memory framing, `"{speaker} said: …"`)
//! is a fixed `"local operator"` — distinct from `"agent"` (the label the
//! agent's own detached retains use) and from any remote/channel speaker
//! name, so a memory fact retained from this REPL is recognisably sourced
//! without claiming to know which human was actually typing.
//!
//! ## Shutdown
//!
//! Ctrl-D (EOF on stdin) or typing `exit`/`quit` ends the loop cleanly.
//! Before returning, `state.chat.drain(...)` is awaited (bounded, same
//! budget as the daemon's own shutdown drain — see `http::server`'s
//! `DRAIN_BUDGET`) so an in-flight detached memory retain from the last
//! turn isn't abandoned mid-write (`ChatHandler::drain`'s doc).

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::Result;
use crate::config::Config;
use crate::domain::Principal;

/// Matches `http::server`'s own shutdown drain budget — no reason for the
/// REPL's exit-time wait to be a different number than the daemon's.
const DRAIN_BUDGET: Duration = Duration::from_secs(20);

/// The label every local-REPL turn is attributed to (see module doc).
pub const LOCAL_SPEAKER: &str = "local operator";

/// Read one line from `input`, returning `None` on EOF (Ctrl-D) — the
/// loop's exit condition. Trims trailing newline only, so leading/trailing
/// spaces inside a real message survive.
fn read_line(input: &mut impl std::io::BufRead) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    let n = input.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(Some(line))
}

/// Run the local chat REPL: boot the daemon's library wiring (no HTTP
/// bind), then loop reading lines from `input` and printing replies to
/// `output` until EOF or `exit`/`quit`. Split out from `run` (which owns
/// the real stdin/stdout) so the loop body is testable against an
/// in-memory `BufRead`/`Vec<u8>` pair without a real TTY.
async fn repl_loop(
    chat: &dyn crate::channels::ChatHandler,
    input: &mut impl std::io::BufRead,
    output: &mut impl Write,
) -> Result<()> {
    writeln!(output, "opsclaw local chat — Ctrl-D or 'exit' to quit").ok();
    loop {
        write!(output, "> ").ok();
        output.flush().ok();
        let Some(line) = read_line(input).map_err(|e| crate::Error::other(e.to_string()))? else {
            writeln!(output).ok();
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "exit" | "quit") {
            break;
        }
        match chat.chat(Principal::System, LOCAL_SPEAKER, trimmed).await {
            Ok(reply) => {
                writeln!(output, "{reply}").ok();
            }
            Err(e) => {
                writeln!(output, "error: {e}").ok();
            }
        }
    }
    chat.drain(DRAIN_BUDGET).await;
    Ok(())
}

/// `opsclaw-cli chat` with no remote gateway configured: load + validate
/// config, boot the full daemon wiring via `boot::daemon_state` (library
/// only — no `server::run`, no bind), then drive the REPL over real
/// stdin/stdout.
pub async fn run(cfg_path: &Path, home: &Path) -> Result<()> {
    let config = Config::load(Some(cfg_path))?;
    config.validate()?;
    let state = crate::boot::daemon_state(config, cfg_path.to_path_buf(), home).await?;

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut output = std::io::stdout();
    repl_loop(state.chat.as_ref(), &mut input, &mut output).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Records every `(principal, speaker, message)` triple it's called
    /// with and echoes a canned or scripted reply — enough to exercise the
    /// loop's control flow without a real agent/LLM.
    #[derive(Default)]
    struct RecordingChat {
        calls: Mutex<Vec<(Principal, String, String)>>,
        drains: AtomicUsize,
    }

    #[async_trait]
    impl crate::channels::ChatHandler for RecordingChat {
        async fn chat(&self, principal: Principal, speaker: &str, message: &str) -> Result<String> {
            self.calls.lock().unwrap().push((principal, speaker.to_string(), message.to_string()));
            if message == "boom" {
                return Err(crate::Error::other("simulated failure"));
            }
            Ok(format!("echo: {message}"))
        }

        async fn drain(&self, _timeout: Duration) -> bool {
            self.drains.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    #[tokio::test]
    async fn quits_cleanly_on_exit() {
        let chat = RecordingChat::default();
        let mut input = std::io::Cursor::new(b"hello\nexit\nnever reached\n".to_vec());
        let mut output = Vec::new();
        repl_loop(&chat, &mut input, &mut output).await.unwrap();

        let calls = chat.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "the line after `exit` must never reach chat()");
        assert_eq!(calls[0].0, Principal::System);
        assert_eq!(calls[0].1, LOCAL_SPEAKER);
        assert_eq!(calls[0].2, "hello");
        assert_eq!(chat.drains.load(Ordering::SeqCst), 1, "drain must run on exit");
    }

    #[tokio::test]
    async fn quits_cleanly_on_quit_alias() {
        let chat = RecordingChat::default();
        let mut input = std::io::Cursor::new(b"quit\n".to_vec());
        let mut output = Vec::new();
        repl_loop(&chat, &mut input, &mut output).await.unwrap();
        assert!(chat.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn quits_cleanly_on_eof_ctrl_d() {
        let chat = RecordingChat::default();
        // No trailing newline at all -> read_line returns 0 bytes read on
        // the NEXT call once the buffer is exhausted, same shape as a real
        // Ctrl-D at an empty prompt.
        let mut input = std::io::Cursor::new(b"".to_vec());
        let mut output = Vec::new();
        repl_loop(&chat, &mut input, &mut output).await.unwrap();
        assert!(chat.calls.lock().unwrap().is_empty());
        assert_eq!(chat.drains.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn blank_lines_are_skipped_not_sent() {
        let chat = RecordingChat::default();
        let mut input = std::io::Cursor::new(b"\n   \nreal message\nexit\n".to_vec());
        let mut output = Vec::new();
        repl_loop(&chat, &mut input, &mut output).await.unwrap();

        let calls = chat.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].2, "real message");
    }

    #[tokio::test]
    async fn reply_is_printed() {
        let chat = RecordingChat::default();
        let mut input = std::io::Cursor::new(b"hi\nexit\n".to_vec());
        let mut output = Vec::new();
        repl_loop(&chat, &mut input, &mut output).await.unwrap();
        let printed = String::from_utf8(output).unwrap();
        assert!(printed.contains("echo: hi"), "{printed}");
    }

    #[tokio::test]
    async fn a_turn_error_is_shown_and_the_loop_continues() {
        let chat = RecordingChat::default();
        let mut input = std::io::Cursor::new(b"boom\nafter\nexit\n".to_vec());
        let mut output = Vec::new();
        repl_loop(&chat, &mut input, &mut output).await.unwrap();

        let calls = chat.calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "a failed turn must not end the loop");
        assert_eq!(calls[1].2, "after");
        let printed = String::from_utf8(output).unwrap();
        assert!(printed.contains("error: simulated failure"), "{printed}");
    }
}
