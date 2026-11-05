//! Sign-in through any OpenID Connect provider (`auth.provider = "oidc"`).
//!
//! Authorization code flow with PKCE (S256), `state` and `nonce`. The ID
//! token is verified here against the IdP's published keys (JWKS): the
//! signature, `iss`, `aud`, `exp` and `nonce`. Nothing about the IdP is
//! assumed beyond the OIDC discovery document, so Entra ID, Okta, Google,
//! Keycloak and Auth0 all work the same way. SAML-only IdPs connect through
//! an OIDC bridge (Keycloak, for example).
//!
//! The daemon then mints its own session cookie, as for every provider, and
//! stores the person's groups from `groups_claim` for the access rules.

use std::time::{Duration, Instant};

use base64::Engine;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::config::OidcCfg;
use crate::{Error, Result};

const CACHE_FOR: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// Who signed in, as the IdP vouches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdentity {
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

/// What the browser carries between `start` and `callback` (inside a
/// signed, short-lived cookie).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pending {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
}

pub struct OidcClient {
    cfg: OidcCfg,
    secret: Option<String>,
    http: reqwest::Client,
    discovery: Mutex<Option<(Instant, Discovery)>>,
    jwks: Mutex<Option<(Instant, JwkSet)>>,
}

fn random_token() -> String {
    use rand::Rng;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

pub fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

impl OidcClient {
    pub fn new(cfg: &OidcCfg, secret: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| Error::other(format!("oidc http client: {e}")))?;
        Ok(OidcClient {
            cfg: cfg.clone(),
            secret,
            http,
            discovery: Mutex::new(None),
            jwks: Mutex::new(None),
        })
    }

    pub fn config(&self) -> &OidcCfg {
        &self.cfg
    }

    async fn discovery(&self) -> Result<Discovery> {
        let mut cached = self.discovery.lock().await;
        if let Some((at, d)) = &*cached
            && at.elapsed() < CACHE_FOR
        {
            return Ok(d.clone());
        }
        let url =
            format!("{}/.well-known/openid-configuration", self.cfg.issuer.trim_end_matches('/'));
        let d: Discovery = self
            .http
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| Error::unavailable(format!("oidc discovery {url}: {e}")))?
            .json()
            .await
            .map_err(|e| Error::unavailable(format!("oidc discovery {url}: {e}")))?;
        if d.issuer.trim_end_matches('/') != self.cfg.issuer.trim_end_matches('/') {
            return Err(Error::Config(format!(
                "oidc issuer mismatch: config says {}, discovery says {}",
                self.cfg.issuer, d.issuer
            )));
        }
        *cached = Some((Instant::now(), d.clone()));
        Ok(d)
    }

    async fn keys(&self, uri: &str, refresh: bool) -> Result<JwkSet> {
        let mut cached = self.jwks.lock().await;
        if !refresh
            && let Some((at, k)) = &*cached
            && at.elapsed() < CACHE_FOR
        {
            return Ok(k.clone());
        }
        let k: JwkSet = self
            .http
            .get(uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| Error::unavailable(format!("oidc keys {uri}: {e}")))?
            .json()
            .await
            .map_err(|e| Error::unavailable(format!("oidc keys {uri}: {e}")))?;
        *cached = Some((Instant::now(), k.clone()));
        Ok(k)
    }

    /// The IdP URL to send the browser to, and what to remember until the
    /// callback.
    pub async fn start(&self) -> Result<(String, Pending)> {
        let d = self.discovery().await?;
        let pending =
            Pending { state: random_token(), nonce: random_token(), verifier: random_token() };
        let mut url = url::Url::parse(&d.authorization_endpoint)
            .map_err(|e| Error::Config(format!("oidc authorization_endpoint: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.cfg.redirect_url)
            .append_pair("scope", &self.cfg.scopes.join(" "))
            .append_pair("state", &pending.state)
            .append_pair("nonce", &pending.nonce)
            .append_pair("code_challenge", &pkce_challenge(&pending.verifier))
            .append_pair("code_challenge_method", "S256");
        Ok((url.into(), pending))
    }

    /// Exchange the code and verify the ID token.
    pub async fn finish(&self, code: &str, pending: &Pending) -> Result<OidcIdentity> {
        let d = self.discovery().await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.cfg.redirect_url.as_str()),
            ("client_id", self.cfg.client_id.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ];
        if let Some(secret) = &self.secret {
            form.push(("client_secret", secret.as_str()));
        }
        let resp = self
            .http
            .post(&d.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| Error::unavailable(format!("oidc token endpoint: {e}")))?;
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| Error::unavailable(format!("oidc token endpoint: {e}")))?;
        if !status.is_success() {
            let why = body["error_description"].as_str().or(body["error"].as_str()).unwrap_or("");
            return Err(Error::unauthorized(format!(
                "sign-in refused by the identity provider: {why}"
            )));
        }
        let id_token = body["id_token"]
            .as_str()
            .ok_or_else(|| Error::unauthorized("the identity provider returned no id_token"))?;
        self.verify(id_token, &pending.nonce, &d).await
    }

    async fn verify(&self, id_token: &str, nonce: &str, d: &Discovery) -> Result<OidcIdentity> {
        let header =
            decode_header(id_token).map_err(|e| Error::unauthorized(format!("id_token: {e}")))?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::ES256
                | Algorithm::ES384
                | Algorithm::PS256
        ) {
            return Err(Error::unauthorized(format!(
                "id_token algorithm {:?} refused",
                header.alg
            )));
        }
        let kid = header.kid.clone().unwrap_or_default();
        let mut keys = self.keys(&d.jwks_uri, false).await?;
        if keys.find(&kid).is_none() {
            // Key rotation: fetch again once.
            keys = self.keys(&d.jwks_uri, true).await?;
        }
        let jwk = keys
            .find(&kid)
            .or_else(|| (keys.keys.len() == 1 && kid.is_empty()).then(|| &keys.keys[0]))
            .ok_or_else(|| Error::unauthorized("id_token signed with an unknown key"))?;
        let key = DecodingKey::from_jwk(jwk)
            .map_err(|e| Error::unauthorized(format!("id_token key: {e}")))?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[d.issuer.as_str()]);
        validation.set_audience(&[self.cfg.client_id.as_str()]);
        validation.leeway = 60;
        let claims = decode::<Value>(id_token, &key, &validation)
            .map_err(|e| Error::unauthorized(format!("id_token rejected: {e}")))?
            .claims;
        identity_from_claims(&self.cfg, &claims, nonce)
    }
}

/// Pull the identity out of verified claims (split out for tests).
pub fn identity_from_claims(cfg: &OidcCfg, claims: &Value, nonce: &str) -> Result<OidcIdentity> {
    if claims["nonce"].as_str() != Some(nonce) {
        return Err(Error::unauthorized("id_token nonce does not match this sign-in"));
    }
    let subject = claims["sub"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::unauthorized("id_token has no subject"))?
        .to_string();
    // An email the IdP says is unverified is not used for anything.
    let email = claims[cfg.email_claim.as_str()]
        .as_str()
        .filter(|_| claims["email_verified"].as_bool() != Some(false))
        .map(str::to_string);
    let name = claims["name"].as_str().map(str::to_string);
    let groups = match &claims[cfg.groups_claim.as_str()] {
        Value::Array(items) => {
            items.iter().filter_map(|g| g.as_str().map(str::to_string)).collect()
        }
        Value::String(one) => vec![one.clone()],
        _ => Vec::new(),
    };
    Ok(OidcIdentity { subject, email, name, groups })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> OidcCfg {
        toml::from_str(
            r#"
            issuer = "https://idp.example"
            client_id = "opsclaw"
            redirect_url = "https://ops.example/api/auth/oidc/callback"
            groups_claim = "roles"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn identity_takes_groups_from_the_configured_claim() {
        let c = json!({"sub": "s1", "nonce": "n", "email": "a@x.com", "roles": ["OpsClaw.Reader"], "name": "A"});
        let id = identity_from_claims(&cfg(), &c, "n").unwrap();
        assert_eq!(id.subject, "s1");
        assert_eq!(id.email.as_deref(), Some("a@x.com"));
        assert_eq!(id.groups, vec!["OpsClaw.Reader".to_string()]);
    }

    #[test]
    fn a_wrong_nonce_or_unverified_email_is_refused() {
        let c = json!({"sub": "s1", "nonce": "other"});
        assert!(identity_from_claims(&cfg(), &c, "n").is_err());
        let c = json!({"sub": "s1", "nonce": "n", "email": "a@x.com", "email_verified": false});
        assert_eq!(identity_from_claims(&cfg(), &c, "n").unwrap().email, None);
    }

    #[test]
    fn pkce_matches_the_rfc_example() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
