//! Secret scrubber (DESIGN §4): every secret value the store can resolve is
//! registered here at resolution time and replaced with `<redacted:NAME>` in
//! tool output, audit records, and log lines *before* they are persisted or
//! enter LLM context — the runtime counterpart of config's `Debug` redaction.
//! A remote `env` dump must not leak a credential into the transcript.

use std::sync::RwLock;

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
}
