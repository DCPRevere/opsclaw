//! Remote-CLI authentication (DESIGN §1/§7: token-auth against the daemon's
//! gateway, gianna's `gcli_` pattern — renamed `ops_` here). Ported from
//! gianna's `src/cli_auth.rs`.
//!
//! The flow is PKCE-shaped:
//! 1. The CLI generates a random `verifier`, derives `challenge =
//!    sha256(verifier)`, and opens the browser at `/cli-auth?challenge=…`.
//! 2. The signed-in operator approves (`POST /api/cli/authorize`), minting a
//!    one-time code bound to the challenge.
//! 3. The CLI exchanges `code + verifier` at `POST /cli/v1/auth/token`. The
//!    server re-derives the challenge, so an intercepted code is useless
//!    without the verifier, which never left the CLI process.
//!
//! The minted token is stored ONLY as a SHA-256 hash (`db::TokenRepo`);
//! revocable per token, all revoked on password reset (`token_version`
//! bump doesn't touch these — CLI tokens are a SEPARATE, independently
//! revocable session kind, matching gianna's stance that the web JWT and
//! the CLI bearer must never be interchangeable).

use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};

/// Tokens are prefixed so a leaked one is recognisable in logs/scanners and
/// can never be mistaken for a web JWT (or vice versa).
pub const TOKEN_PREFIX: &str = "ops_";

/// One-time authorization codes expire after this long.
pub const CODE_TTL_SECS: i64 = 600;

/// A pending one-time authorization code, held in memory until exchanged.
/// Transient by design: a restart mid-login just means re-running `login`
/// (opsclaw is a single-node daemon — DESIGN §1).
pub struct PendingCliAuth {
    pub account_id: uuid::Uuid,
    /// sha256 hex of the CLI's verifier — the exchange must prove knowledge of it.
    pub challenge: String,
    /// Device label for the token row (the CLI sends its hostname).
    pub name: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
}

/// code -> pending authorization, swept on insert.
pub type CliAuthCodes = std::collections::HashMap<String, PendingCliAuth>;

fn random_urlsafe(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh PKCE verifier (CLI side).
pub fn generate_verifier() -> String {
    random_urlsafe(32)
}

/// The challenge derived from a verifier — safe to travel via the browser.
pub fn challenge_for(verifier: &str) -> String {
    sha256_hex(verifier)
}

/// A fresh one-time authorization code (server side).
pub fn generate_code() -> String {
    random_urlsafe(32)
}

/// A fresh CLI access token (server side; plaintext returned exactly once).
pub fn generate_token() -> String {
    format!("{TOKEN_PREFIX}{}", random_urlsafe(32))
}

/// The hash under which a CLI token is stored and looked up — the
/// plaintext never touches the database.
pub fn token_hash(token: &str) -> String {
    sha256_hex(token)
}

/// Under SSO, CLI tokens expire (`auth.oidc.cli_token_hours`), so a person
/// removed at the IdP loses the CLI too: they can't sign in again to mint
/// a new one. Other providers keep tokens until revoked.
pub(crate) async fn check_token_age(
    state: &crate::http::state::AppState,
    token_id: uuid::Uuid,
    account: uuid::Uuid,
) -> crate::Result<()> {
    let hours = match (&state.config.auth.provider, &state.config.auth.oidc) {
        (crate::config::AuthProvider::Oidc, Some(o)) if o.cli_token_hours > 0 => o.cli_token_hours,
        _ => return Ok(()),
    };
    let tokens = state.repos.list_cli_tokens(account).await?;
    let created = tokens
        .iter()
        .find(|t| t.id == token_id)
        .map(|t| t.created_at)
        .ok_or_else(|| crate::Error::unauthorized("token revoked — run `opsclaw-cli login`"))?;
    if created + chrono::Duration::hours(hours as i64) < chrono::Utc::now() {
        return Err(crate::Error::unauthorized(
            "CLI session expired — run `opsclaw-cli login` to sign in again",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_deterministic_and_distinct() {
        let v = generate_verifier();
        assert_eq!(challenge_for(&v), challenge_for(&v));
        assert_ne!(challenge_for(&v), v);
        assert_eq!(challenge_for(&v).len(), 64); // sha256 hex
        assert_ne!(generate_verifier(), generate_verifier());
    }

    #[test]
    fn tokens_are_prefixed_and_hash_hides_them() {
        let t = generate_token();
        assert!(t.starts_with(TOKEN_PREFIX));
        assert_ne!(token_hash(&t), t);
        assert_eq!(token_hash(&t).len(), 64);
    }
}
