//! VAPID keypair generation for `opsclaw-cli onboard` (DESIGN.md §4 HTTP
//! gateway: "`onboard` generates the per-deployment VAPID keypair (gianna's
//! `validate()` lesson: reject a half-set pair)").
//!
//! No standalone VAPID-keygen exists to port from gianna — gianna's
//! `push.rs` only *validates* an existing pair (`validate_vapid_pair`), the
//! keys having been generated once, externally. This module writes that
//! generator from scratch, using ONLY what's already reachable from
//! `Cargo.toml`'s declared dependencies:
//!   - `web-push-native = "0.4.0"` publicly re-exports `p256` at its crate
//!     root (`pub use p256;`, confirmed by reading its `src/lib.rs`) — so
//!     `web_push_native::p256::SecretKey` is a supported part of that
//!     crate's own public API, not an undeclared transitive dependency.
//!   - `base64 = "0.22"` (top-level, declared) provides URL-safe-no-pad
//!     encoding, in preference to the transitive `base64ct` crate
//!     web-push-native happens to use internally (same output format —
//!     unpadded base64url — for the raw bytes VAPID keys are conventionally
//!     stored as).
//!
//! `rand = "0.10"` (top-level, declared) is deliberately NOT used to drive
//! the keygen: `p256::SecretKey::random` needs an `rand_core 0.6`-compatible
//! RNG (that's the `rand_core` version pinned by `p256 0.13.2`'s own
//! dependency graph), and the top-level `rand 0.10` crate pins `rand_core
//! 0.10.x` — a different major version with an incompatible `RngCore` trait,
//! so `rand::rng()` cannot be passed here directly. `p256`'s own re-exported
//! `elliptic_curve::rand_core::OsRng` (itself just a re-export of the
//! `getrandom`-backed OS RNG, already in the dependency tree as a transitive
//! dependency of `p256` itself, not a new one we're introducing) is what
//! satisfies the trait bound `SecretKey::random` actually requires.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use web_push_native::p256;
use web_push_native::p256::elliptic_curve::rand_core::OsRng;
use web_push_native::p256::elliptic_curve::sec1::ToEncodedPoint;

/// A generated VAPID keypair, base64url-nopad encoded (the wire/storage
/// convention `web-push`/VAPID implementations use — `web_push_native`'s own
/// `serde_.rs` decodes public keys the same way).
pub struct VapidKeypair {
    /// Raw 32-byte P-256 private scalar, base64url-nopad.
    pub private_key: String,
    /// Uncompressed SEC1 public point (65 bytes: 0x04 || X(32) || Y(32)),
    /// base64url-nopad — the form browsers' `applicationServerKey` expects.
    pub public_key: String,
}

/// Generate a fresh VAPID keypair. Never reuses or derives from anything —
/// every call is an independent random keypair (gianna's push.rs comment:
/// VAPID keys must "never rotate" once issued, precisely because rotating
/// breaks every subscribed device — so generation only ever happens once,
/// at onboard time, never silently regenerated on a later `doctor`/`onboard
/// --yes` re-run against an existing config).
pub fn generate() -> VapidKeypair {
    let secret = p256::SecretKey::random(&mut OsRng);
    let private_bytes: [u8; 32] = secret.to_bytes().into();
    let public_point = secret.public_key().to_encoded_point(false);

    VapidKeypair {
        private_key: URL_SAFE_NO_PAD.encode(private_bytes),
        public_key: URL_SAFE_NO_PAD.encode(public_point.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_well_formed_keys() {
        let kp = generate();
        // 32 raw bytes -> 43 base64url-nopad chars (ceil(32*8/6)).
        assert_eq!(kp.private_key.len(), 43);
        // 65 raw bytes (uncompressed point) -> 87 base64url-nopad chars.
        assert_eq!(kp.public_key.len(), 87);
        assert!(URL_SAFE_NO_PAD.decode(&kp.private_key).is_ok());
        assert!(URL_SAFE_NO_PAD.decode(&kp.public_key).is_ok());
    }

    #[test]
    fn never_reuses_keys_across_calls() {
        let a = generate();
        let b = generate();
        assert_ne!(a.private_key, b.private_key);
        assert_ne!(a.public_key, b.public_key);
    }

    #[test]
    fn public_key_is_uncompressed_sec1_point() {
        let kp = generate();
        let raw = URL_SAFE_NO_PAD.decode(&kp.public_key).unwrap();
        assert_eq!(raw.len(), 65);
        assert_eq!(raw[0], 0x04, "expected uncompressed SEC1 point prefix");
    }
}
