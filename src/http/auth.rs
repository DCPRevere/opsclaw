//! Auth primitives: argon2 password hashing and HS256 JWT session/scoped
//! tokens. Ported from gianna's `src/http/auth.rs` — same shapes, renamed
//! `hh`/`household_id` away (opsclaw is single-tenant; no household to
//! carry in a claim) and the cookie name/env-derived constants localized.

use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, Result};

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::other(format!("hash: {e}")))
}

/// The `password_hash` written for an account that authenticates through an
/// external provider (`auth.provider = "hanko"`). Deliberately NOT a valid
/// PHC string, so it can never be reached by an argon2 verify: the column is
/// `NOT NULL` in migration 0001 and SQLite cannot relax that in place, so a
/// passwordless account needs a sentinel rather than a null.
pub const NO_PASSWORD: &str = "!no-password";

/// Verify a password against a stored hash.
///
/// An unusable stored hash is `Ok(false)`, never `Err`. `Error::other` maps
/// to a 500 (`http::mod`), and a 500 where every other account yields a 401
/// turns `POST /api/login` into an account-existence oracle — it would leak
/// exactly which emails belong to externally-authenticated operators,
/// defeating the uniform "invalid email or password" response.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    if hash == NO_PASSWORD {
        return Ok(false);
    }
    let Ok(parsed) = PasswordHash::new(hash) else {
        // Never log the hash or the password — only that the row is
        // unusable, so an operator can find it without the journal
        // becoming a credential store.
        tracing::warn!("stored password hash is not a valid PHC string — refusing sign-in");
        return Ok(false);
    };
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Operator session claims. No household/team id — opsclaw is single-tenant
/// (DESIGN §1: "no tenancy ids thread through the code").
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// account id
    pub sub: String,
    pub exp: usize,
    /// The account's `token_version` at issue time — a password reset or
    /// explicit "sign out everywhere" bumps it, revoking every previously
    /// issued token. Defaults to 0 so a token issued before this field
    /// existed stays valid until the account's first reset.
    #[serde(default)]
    pub ver: i64,
}

/// Session token lifetime. Short (bounds the theft window); active
/// operators are kept signed in by sliding refresh — a fresh cookie is
/// issued once a token passes its half-life (see [`should_refresh`]).
pub const SESSION_TTL_DAYS: i64 = 7;

/// The HttpOnly session cookie's name. The web UI authenticates by this
/// cookie only (the token never reaches JavaScript); the remote CLI keeps
/// its own Bearer path (`ops_`-prefixed token, see `cli_auth`).
pub const SESSION_COOKIE: &str = "opsclaw_session";

pub fn issue_token(secret: &str, account_id: Uuid, ver: i64) -> Result<String> {
    let exp = (Utc::now() + Duration::days(SESSION_TTL_DAYS)).timestamp() as usize;
    let claims = Claims { sub: account_id.to_string(), exp, ver };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .map_err(|e| Error::other(format!("jwt encode: {e}")))
}

/// True when a still-valid token has passed its half-life and should be
/// re-issued (sliding session). `exp` is the token's expiry epoch seconds.
pub fn should_refresh(exp: usize) -> bool {
    let now = Utc::now().timestamp();
    let exp = exp as i64;
    let half_life_secs = Duration::days(SESSION_TTL_DAYS).num_seconds() / 2;
    exp > now && (exp - now) < half_life_secs
}

/// Build the `Set-Cookie` value for the session token. `secure` gates the
/// `Secure` attribute (config's `http.cookies_secure`, defaults true).
/// `HttpOnly` keeps the token out of JS (the XSS-theft mitigation);
/// `SameSite=Strict` is the CSRF defense for this same-origin app.
pub fn session_cookie(token: &str, secure: bool) -> String {
    let max_age = Duration::days(SESSION_TTL_DAYS).num_seconds();
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure_attr}"
    )
}

/// Build the `Set-Cookie` value that CLEARS the session cookie (logout):
/// same attributes, empty value, `Max-Age=0` so the browser drops it
/// immediately.
pub fn clear_session_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure_attr}")
}

/// Read the session token from a request's `Cookie` header (the web UI's
/// auth path).
pub fn session_cookie_value(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.trim() == SESSION_COOKIE).then(|| v.trim().to_string())
    })
}

pub fn verify_token(secret: &str, token: &str) -> Result<Claims> {
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default())
        .map(|d| d.claims)
        .map_err(|e| {
            // Log the FAILURE KIND (never the token). ExpiredSignature is a
            // benign session timeout; InvalidSignature/InvalidToken means a
            // wrong secret, clock skew, or tampering.
            tracing::debug!(jwt_err = ?e.kind(), "session token rejected");
            Error::unauthorized("invalid or expired token")
        })
}

/// A short-lived, purpose-scoped token (SSE stream tickets, the CLI PKCE
/// exchange's browser-side leg). `purpose` binds the token to one use-case
/// so a stream ticket can't be replayed as, say, a CLI code; `bind` ties it
/// to a piece of current state when the caller wants single-use-by-state
/// semantics — opsclaw's SSE ticket leaves it empty and relies on the
/// separate in-memory replay guard instead (see `http::sse`).
#[derive(Debug, Serialize, Deserialize)]
pub struct ScopedClaims {
    pub sub: String, // account id
    pub purpose: String,
    pub exp: usize,
    #[serde(default)]
    pub bind: String,
}

pub fn issue_scoped(
    secret: &str,
    account_id: Uuid,
    purpose: &str,
    ttl: Duration,
    bind: &str,
) -> Result<String> {
    let exp = (Utc::now() + ttl).timestamp() as usize;
    let claims = ScopedClaims {
        sub: account_id.to_string(),
        purpose: purpose.to_string(),
        exp,
        bind: bind.to_string(),
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .map_err(|e| Error::other(format!("jwt encode: {e}")))
}

/// Verify a scoped token and return the account id, checking the purpose matches.
pub fn verify_scoped(secret: &str, token: &str, expected_purpose: &str) -> Result<Uuid> {
    Ok(verify_scoped_claims(secret, token, expected_purpose)?.0)
}

/// Like [`verify_scoped`], also returning the token's state binding.
pub fn verify_scoped_claims(
    secret: &str,
    token: &str,
    expected_purpose: &str,
) -> Result<(Uuid, String)> {
    let claims = decode::<ScopedClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|d| d.claims)
    .map_err(|e| {
        tracing::debug!(jwt_err = ?e.kind(), purpose = %expected_purpose, "scoped token rejected");
        Error::unauthorized("invalid or expired token")
    })?;
    if claims.purpose != expected_purpose {
        tracing::debug!(got = %claims.purpose, expected = %expected_purpose, "scoped token purpose mismatch");
        return Err(Error::unauthorized("token not valid for this action"));
    }
    let id = claims.sub.parse().map_err(|_| Error::unauthorized("bad token"))?;
    Ok((id, claims.bind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let h = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn no_password_sentinel_never_verifies() {
        assert!(!verify_password("", NO_PASSWORD).unwrap());
        assert!(!verify_password(NO_PASSWORD, NO_PASSWORD).unwrap());
        assert!(!verify_password("correct horse", NO_PASSWORD).unwrap());
    }

    #[test]
    fn garbage_hash_is_rejected_not_an_error() {
        // Ok(false), never Err: an Err here is a 500 among 401s, which is
        // an account-existence oracle.
        assert!(!verify_password("anything", "not-a-phc-string").unwrap());
        assert!(!verify_password("anything", "").unwrap());
    }

    #[test]
    fn token_round_trip() {
        let a = Uuid::new_v4();
        let tok = issue_token("a-strong-enough-test-secret-123456", a, 0).unwrap();
        let claims = verify_token("a-strong-enough-test-secret-123456", &tok).unwrap();
        assert_eq!(claims.sub, a.to_string());
        assert!(verify_token("other-secret", &tok).is_err());
    }

    #[test]
    fn revoked_version_is_caught_by_the_caller_comparing_ver() {
        // The version check itself lives in authenticate() (it needs the
        // account row); this test just pins that `ver` round-trips so that
        // comparison is meaningful.
        let a = Uuid::new_v4();
        let tok = issue_token("a-strong-enough-test-secret-123456", a, 3).unwrap();
        let claims = verify_token("a-strong-enough-test-secret-123456", &tok).unwrap();
        assert_eq!(claims.ver, 3);
    }

    #[test]
    fn should_refresh_only_past_half_life() {
        let now = Utc::now().timestamp() as usize;
        let day = Duration::days(1).num_seconds() as usize;
        assert!(!should_refresh(now + 7 * day));
        assert!(should_refresh(now + 3 * day));
        assert!(!should_refresh(now.saturating_sub(day)));
    }

    #[test]
    fn session_cookie_carries_security_attributes() {
        let c = session_cookie("abc.def.ghi", true);
        assert!(c.starts_with("opsclaw_session=abc.def.ghi"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("Secure"));
        assert!(!session_cookie("t", false).contains("Secure"));
        assert!(clear_session_cookie(true).contains("Max-Age=0"));
    }

    #[test]
    fn reads_session_token_from_cookie_header() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "other=1; opsclaw_session=the-token; theme=dark".parse().unwrap(),
        );
        assert_eq!(session_cookie_value(&h).as_deref(), Some("the-token"));
        assert_eq!(session_cookie_value(&axum::http::HeaderMap::new()), None);
    }

    #[test]
    fn scoped_token_round_trip_and_purpose_gate() {
        let a = Uuid::new_v4();
        let tok = issue_scoped(
            "a-strong-enough-test-secret-123456",
            a,
            "sse",
            Duration::seconds(60),
            "bound",
        )
        .unwrap();
        let (id, bind) =
            verify_scoped_claims("a-strong-enough-test-secret-123456", &tok, "sse").unwrap();
        assert_eq!(id, a);
        assert_eq!(bind, "bound");

        // Wrong purpose is rejected even with the right secret.
        assert!(verify_scoped("a-strong-enough-test-secret-123456", &tok, "cli").is_err());
    }
}
