//! A small fixed-window rate limiter for abuse-prone endpoints (login, CLI
//! code exchange). Ported verbatim from gianna's `src/http/ratelimit.rs`.
//!
//! In-memory and per-key (IP for unauthenticated routes). Good enough to
//! blunt login/CLI-exchange abuse against a single-node daemon reached over
//! a tunnel/VPN (DESIGN §3) — there is no reverse-proxy-in-front assumption
//! to lean on here the way gianna's deploy notes do.

use std::collections::HashMap;
use std::sync::Mutex;

/// Fixed-window counter. `allow_at` returns false when the key exceeds
/// `max` hits within `window_secs` (windows are derived from a caller-
/// supplied timestamp so the limiter is testable without a clock).
pub struct RateLimiter {
    max: u32,
    window_secs: i64,
    hits: Mutex<HashMap<String, (i64, u32)>>, // key -> (window_start, count)
}

impl RateLimiter {
    pub fn new(max: u32, window_secs: i64) -> Self {
        Self { max, window_secs, hits: Mutex::new(HashMap::new()) }
    }

    /// Record a hit for `key` at unix time `now`. Returns true if allowed.
    pub fn allow_at(&self, key: &str, now: i64) -> bool {
        let window = now / self.window_secs;
        let mut m = self.hits.lock().unwrap();
        // Eviction: every distinct key (IP) would otherwise be a permanent
        // entry — sweep past-window entries once the map is non-trivial.
        if m.len() > 4096 {
            m.retain(|_, (w, _)| *w == window);
        }
        let entry = m.entry(key.to_string()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_limit_then_resets_next_window() {
        let rl = RateLimiter::new(3, 60);
        let t = 1_000_000;
        assert!(rl.allow_at("ip", t));
        assert!(rl.allow_at("ip", t));
        assert!(rl.allow_at("ip", t));
        assert!(!rl.allow_at("ip", t));
        assert!(rl.allow_at("ip", t + 60));
        assert!(rl.allow_at("other", t));
    }
}
