//! Secret scrubber (DESIGN §4): every secret value the store can resolve is
//! registered here at resolution time and replaced with `<redacted:NAME>` in
//! tool output, audit records, and log lines *before* they are persisted or
//! enter LLM context — the runtime counterpart of config's `Debug` redaction.
//! A remote `env` dump must not leak a credential into the transcript.

use std::sync::{Arc, Mutex, RwLock};

/// Values shorter than this are never registered: scrubbing a 1–3 char
/// "secret" would shred ordinary text (and no real credential is that short).
const MIN_SECRET_LEN: usize = 4;

#[derive(Default)]
pub struct Scrubber {
    /// (name, value), kept sorted by value length descending so a secret that
    /// contains another secret is replaced whole, not inside-out.
    entries: RwLock<Vec<(String, String)>>,
}

impl Scrubber {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a resolved secret. Idempotent per (name, value); re-registering
    /// the same name with a rotated value scrubs both old and new.
    pub fn register(&self, name: &str, value: &str) {
        if value.len() < MIN_SECRET_LEN {
            return;
        }
        let mut entries = self.entries.write().expect("scrubber lock poisoned");
        if entries.iter().any(|(n, v)| n == name && v == value) {
            return;
        }
        entries.push((name.to_string(), value.to_string()));
        entries.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    }

    /// Replace every registered secret value in `text` with `<redacted:NAME>`.
    pub fn scrub(&self, text: &str) -> String {
        let entries = self.entries.read().expect("scrubber lock poisoned");
        let mut out = text.to_string();
        for (name, value) in entries.iter() {
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), &format!("<redacted:{name}>"));
            }
        }
        out
    }

    /// The process-wide scrubber instance the LOG SINK is wired to (DoD #4:
    /// no secret in any log line). It must exist BEFORE tracing init —
    /// which happens before `boot::daemon_state` runs — so it's a static;
    /// boot uses this same instance as the policy scrubber, and every
    /// registration therefore covers tool output, audit records, AND log
    /// lines with no second registry to drift. Tests that want isolation
    /// keep constructing their own `Scrubber::new()`.
    pub fn global() -> &'static Arc<Scrubber> {
        static GLOBAL: std::sync::LazyLock<Arc<Scrubber>> =
            std::sync::LazyLock::new(|| Arc::new(Scrubber::new()));
        &GLOBAL
    }
}

/// A `tracing_subscriber` `MakeWriter` that scrubs every formatted event
/// through a [`Scrubber`] before it reaches the real sink — the log-line
/// half of DESIGN §4's "tool output, log lines, and audit records". The fmt
/// layer writes one whole formatted event per writer instance, so buffering
/// until drop sees the complete line (a secret can't straddle two events).
pub struct ScrubbingMakeWriter {
    scrubber: Arc<Scrubber>,
    /// `None` ⇒ stdout (the daemon's normal sink); `Some` ⇒ captured, for
    /// tests asserting on the scrubbed output.
    capture: Option<Arc<Mutex<Vec<String>>>>,
}

impl ScrubbingMakeWriter {
    pub fn stdout(scrubber: Arc<Scrubber>) -> Self {
        ScrubbingMakeWriter { scrubber, capture: None }
    }

    /// A capturing variant for tests: returns the writer plus the shared
    /// buffer the scrubbed lines land in.
    pub fn capturing(scrubber: Arc<Scrubber>) -> (Self, Arc<Mutex<Vec<String>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (ScrubbingMakeWriter { scrubber, capture: Some(buf.clone()) }, buf)
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ScrubbingMakeWriter {
    type Writer = ScrubbingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ScrubbingWriter {
            scrubber: self.scrubber.clone(),
            capture: self.capture.clone(),
            buf: Vec::new(),
        }
    }
}

pub struct ScrubbingWriter {
    scrubber: Arc<Scrubber>,
    capture: Option<Arc<Mutex<Vec<String>>>>,
    buf: Vec<u8>,
}

impl std::io::Write for ScrubbingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for ScrubbingWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.buf);
        let scrubbed = self.scrubber.scrub(&text);
        match &self.capture {
            Some(buf) => buf.lock().expect("capture lock").push(scrubbed),
            None => {
                use std::io::Write;
                let _ = std::io::stdout().write_all(scrubbed.as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_registered_values_with_names() {
        let s = Scrubber::new();
        s.register("DB_PASSWORD", "hunter22");
        assert_eq!(
            s.scrub("PGPASSWORD=hunter22 psql -h db"),
            "PGPASSWORD=<redacted:DB_PASSWORD> psql -h db"
        );
    }

    #[test]
    fn longer_secret_wins_when_nested() {
        let s = Scrubber::new();
        s.register("SHORT", "abcd1234");
        s.register("LONG", "xxabcd1234yy");
        assert_eq!(s.scrub("token=xxabcd1234yy"), "token=<redacted:LONG>");
    }

    #[test]
    fn short_values_never_registered() {
        let s = Scrubber::new();
        s.register("TINY", "ab");
        assert_eq!(s.scrub("ab abab"), "ab abab");
    }

    #[test]
    fn rotated_value_scrubs_old_and_new() {
        let s = Scrubber::new();
        s.register("KEY", "old-secret");
        s.register("KEY", "new-secret");
        assert_eq!(s.scrub("old-secret new-secret"), "<redacted:KEY> <redacted:KEY>");
    }

    #[test]
    fn untouched_text_passes_through() {
        let s = Scrubber::new();
        s.register("KEY", "supersecret");
        assert_eq!(s.scrub("nothing to see"), "nothing to see");
    }

    #[test]
    fn log_sink_scrubs_a_known_secret_out_of_a_traced_line() {
        // The DoD #4 log-line sink test: feed a known secret through a real
        // tracing subscriber wired to the scrubbing writer and assert it
        // never surfaces in the emitted line.
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let scrubber = Arc::new(Scrubber::new());
        scrubber.register("OPENROUTER_API_KEY", "sk-or-v1-abcdef123456");
        let (writer, captured) = ScrubbingMakeWriter::capturing(scrubber);
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(writer));
        let _guard = subscriber.set_default();

        tracing::error!("chain build failed with key sk-or-v1-abcdef123456 rejected");

        let lines = captured.lock().unwrap();
        let joined = lines.join("\n");
        assert!(!joined.contains("sk-or-v1-abcdef123456"), "raw secret leaked: {joined}");
        assert!(joined.contains("<redacted:OPENROUTER_API_KEY>"), "{joined}");
    }

    #[test]
    fn global_scrubber_is_one_instance() {
        let a = Scrubber::global();
        let b = Scrubber::global();
        assert!(Arc::ptr_eq(a, b));
    }
}
