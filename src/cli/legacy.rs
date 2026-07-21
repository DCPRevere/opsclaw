//! Legacy-config detection (docs/plans/IMPLEMENTATION.md §5: "machines that
//! ran the zeroclaw-fork opsclaw have an old-schema `~/.opsclaw/config.toml`
//! (`schema_version = 2`) ... `onboard`/`doctor` must detect it and offer
//! migration or a clear refusal, not a raw parse error").
//!
//! The current `Config` schema (`config::Config`) is `#[serde(deny_unknown_fields)]`
//! and has no top-level `schema_version`, `providers`, `autonomy`, etc. — so
//! `toml::from_str::<Config>` on an old-schema file fails on the very first
//! unrecognized key with a generic serde message ("unknown field
//! `schema_version`, expected one of..."), which is technically correct but
//! gives an operator no idea their file is from a different, unrelated
//! product generation rather than just malformed. This module sniffs the raw
//! TOML (parsed as a generic `toml::Value`, never through the strict
//! `Config` type) for the one marker field the old schema always had, so
//! callers can print an actionable message instead of forwarding the raw
//! parse error.

/// True if `raw` parses as TOML and has a top-level `schema_version` key —
/// the zeroclaw-fork marker. Never itself treated as a hard signal of
/// validity: a config with no `schema_version` still goes through the normal
/// `Config::load`/`validate()` path and gets whatever error that produces.
pub fn looks_like_legacy_config(raw: &str) -> bool {
    match raw.parse::<toml::Value>() {
        Ok(toml::Value::Table(t)) => t.contains_key("schema_version"),
        _ => false,
    }
}

pub const LEGACY_CONFIG_MESSAGE: &str = "\
this looks like a config.toml from a different, unrelated opsclaw generation \
(it has a top-level `schema_version` key, which the current schema never \
writes) — not a malformed version of the current format. There is no \
automatic migration path from that schema. Move it aside (e.g. `mv \
config.toml config.toml.pre-rebuild`) and run `opsclaw-cli onboard` to start \
fresh, or hand-author a new config.toml against the current schema \
(docs/DESIGN.md §3 Config).";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_schema_version_marker() {
        assert!(looks_like_legacy_config("schema_version = 2\n[providers]\n"));
    }

    #[test]
    fn current_schema_is_not_flagged() {
        assert!(!looks_like_legacy_config("[daemon]\ntick_seconds = 300\n"));
    }

    #[test]
    fn empty_or_garbage_is_not_flagged() {
        assert!(!looks_like_legacy_config(""));
        assert!(!looks_like_legacy_config("not even toml {{{"));
    }
}
