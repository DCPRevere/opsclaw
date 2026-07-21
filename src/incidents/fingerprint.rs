//! Incident fingerprinting: the anti-spam identity. Two detections that hash
//! to the same fingerprint are the SAME incident (a new occurrence on the
//! existing row), never a new one — this is what makes "one incident, one
//! alert" possible (brief §6).
//!
//! Fingerprint = (fq target, fault class, resource) per DESIGN.md §4. All
//! three fields are free text supplied by the caller (a scan job, a webhook
//! handler, a runbook trigger) — this module only defines the canonical,
//! stable encoding, never how a caller derives "fault class" for a given
//! signal.

use sha2::{Digest, Sha256};

use crate::domain::FqTarget;

/// Canonical fields that identify an incident, independent of any single
/// occurrence's numbers (a CPU spike observed at 91% and one observed at 97%
/// are the same incident if target+fault_class+resource match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintKey<'a> {
    pub target: &'a FqTarget,
    /// The kind of fault, e.g. "cpu_saturation", "dlq_backlog",
    /// "target_unreachable". Free text, but callers should keep a stable,
    /// small vocabulary — this is effectively the incident's "type".
    pub fault_class: &'a str,
    /// The specific resource affected within the target, e.g. a process
    /// name, queue name, or mount point. Empty string when the fault has no
    /// finer-grained resource than the target itself (e.g. "cluster
    /// unreachable").
    pub resource: &'a str,
}

/// Compute the fingerprint: SHA-256 over the canonical, length-framed
/// encoding of (fq target, fault class, resource), hex-encoded. STABLE
/// FORMAT — this is a dedup identity persisted across restarts and used to
/// look up open incidents (`IncidentRepo::find_open_by_fingerprint`);
/// changing the encoding orphans every open incident from new detections
/// that would otherwise have matched it.
///
/// Length-then-value framing (same discipline as `audit::chain::canonical`)
/// so no two distinct triples can collide by concatenation ambiguity, e.g.
/// `("a", "bc")` vs `("ab", "c")`.
pub fn fingerprint(key: FingerprintKey<'_>) -> String {
    let mut buf = Vec::new();
    let mut push = |s: &str| {
        buf.extend_from_slice(s.len().to_string().as_bytes());
        buf.push(b':');
        buf.extend_from_slice(s.as_bytes());
        buf.push(b'\n');
    };
    push(&key.target.to_string());
    push(key.fault_class);
    push(key.resource);
    let digest = Sha256::digest(&buf);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Convenience wrapper taking owned/borrowed strings directly, for callers
/// that don't want to build a [`FingerprintKey`] (most call sites).
pub fn fingerprint_for(target: &FqTarget, fault_class: &str, resource: &str) -> String {
    fingerprint(FingerprintKey { target, fault_class, resource })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str) -> FqTarget {
        FqTarget::new("remundo", "prod", name)
    }

    #[test]
    fn deterministic_across_calls() {
        let t = target("web-1");
        let a = fingerprint_for(&t, "cpu_saturation", "");
        let b = fingerprint_for(&t, "cpu_saturation", "");
        assert_eq!(a, b);
    }

    #[test]
    fn differs_on_target() {
        let a = fingerprint_for(&target("web-1"), "cpu_saturation", "");
        let b = fingerprint_for(&target("web-2"), "cpu_saturation", "");
        assert_ne!(a, b);
    }

    #[test]
    fn differs_on_fault_class() {
        let t = target("web-1");
        let a = fingerprint_for(&t, "cpu_saturation", "");
        let b = fingerprint_for(&t, "disk_full", "");
        assert_ne!(a, b);
    }

    #[test]
    fn differs_on_resource() {
        let t = target("web-1");
        let a = fingerprint_for(&t, "process_flapping", "nginx");
        let b = fingerprint_for(&t, "process_flapping", "postgres");
        assert_ne!(a, b);
    }

    #[test]
    fn no_concatenation_collision_across_field_boundary() {
        // ("ab", "c", "") must not collide with ("a", "bc", "") — the
        // length-framing is what prevents this, not the byte content alone.
        let t1 = target("ab");
        let t2 = target("a");
        let a = fingerprint_for(&t1, "c", "");
        let b = fingerprint_for(&t2, "bc", "");
        assert_ne!(a, b);
    }

    #[test]
    fn stable_hex_format() {
        let f = fingerprint_for(&target("web-1"), "cpu_saturation", "");
        assert_eq!(f.len(), 64, "sha-256 hex digest is 64 chars");
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn resource_distinguishes_same_target_and_fault_class() {
        // Two different mounts filling up on the same host are two distinct
        // incidents, not one.
        let t = target("web-1");
        let a = fingerprint_for(&t, "disk_full", "/data");
        let b = fingerprint_for(&t, "disk_full", "/var/log");
        assert_ne!(a, b);
    }
}
