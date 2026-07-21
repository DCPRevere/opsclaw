//! Team memory via Hindsight. Wave 1 ports gianna's client wholesale
//! (`src/memory/{mod,hindsight}.rs`): one bank per team, `retain_detached`
//! with retries + shutdown drain, 5s read timeouts inside the tool loop,
//! SHA-256 content-hash upsert ids, deterministic pre-retain filtering.
//!
//! This facade freezes the honest-no-op contract: without a backend,
//! `is_enabled()` is false and tools tell the truth ("I can't remember things
//! right now") instead of faking a save — gianna's stance, kept.

/// Memory facade. Wave 1 replaces the internals; the surface is frozen.
pub struct Memory {
    enabled: bool,
}

impl Memory {
    /// No backend attached — the honest no-op (fakes mode).
    pub fn disabled() -> Self {
        Memory { enabled: false }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
