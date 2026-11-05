//! `/api/auth/oidc/start` and `/api/auth/oidc/callback` (`crate::http::oidc`).

use std::collections::HashMap;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{Account, AccountRepo};
use crate::http::handlers::{ClientAddr, check_auth_rate, session_response};
use crate::http::oidc::Pending;
use crate::http::state::AppState;
use crate::{Error, Result};

const PENDING_COOKIE: &str = "opsclaw_oidc";
const PENDING_TTL_SECS: i64 = 600;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/oidc/start", get(start))
        .route("/api/auth/oidc/callback", get(callback))
}

#[derive(Serialize, Deserialize)]
struct PendingClaims {
    purpose: String,
    exp: usize,
    #[serde(flatten)]
    pending: Pending,
}

fn pending_cookie(value: &str, secure: bool, max_age: i64) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    // Lax, not Strict: the IdP's redirect back is a cross-site top-level
    // navigation, and the cookie must ride on it.
    format!(
        "{PENDING_COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/api/auth/oidc; Max-Age={max_age}{secure_attr}"
    )
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(|v| {
        v.split(';').map(str::trim).find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
    })
}

fn client(state: &AppState) -> Result<&crate::http::oidc::OidcClient> {
    state.oidc.as_deref().ok_or_else(|| Error::validation("this daemon does not use SSO sign-in"))
}

/// GET /api/auth/oidc/start: send the browser to the IdP.
async fn start(State(state): State<AppState>, ClientAddr(peer): ClientAddr) -> Result<Response> {
    check_auth_rate(&state, peer)?;
    let (url, pending) = client(&state)?.start().await?;
    let claims = PendingClaims {
        purpose: "oidc".into(),
        exp: (Utc::now().timestamp() + PENDING_TTL_SECS) as usize,
        pending,
    };
    let token =
        encode(&Header::default(), &claims, &EncodingKey::from_secret(state.jwt_secret.as_bytes()))
            .map_err(|e| Error::other(format!("jwt encode: {e}")))?;
    Ok((
        StatusCode::FOUND,
        [
            (header::LOCATION, url),
            (
                header::SET_COOKIE,
                pending_cookie(&token, state.config.http.cookies_secure, PENDING_TTL_SECS),
            ),
        ],
    )
        .into_response())
}

fn page(status: StatusCode, message: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>OpsClaw sign-in</title>\
         <p>{}</p><p><a href=\"/app\">Back to OpsClaw</a></p>",
        html_escape(message)
    );
    (status, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// GET /api/auth/oidc/callback?code&state
async fn callback(
    State(state): State<AppState>,
    ClientAddr(peer): ClientAddr,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response> {
    check_auth_rate(&state, peer)?;
    if let Some(err) = q.get("error") {
        let why = q.get("error_description").map(String::as_str).unwrap_or(err);
        return Ok(page(StatusCode::UNAUTHORIZED, &format!("Sign-in was refused: {why}")));
    }
    let oidc = client(&state)?;
    let token = cookie_value(&headers, PENDING_COOKIE)
        .ok_or_else(|| Error::unauthorized("sign-in expired; start again"))?;
    let validation = Validation {
        required_spec_claims: ["exp".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let claims = decode::<PendingClaims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| Error::unauthorized("sign-in expired; start again"))?
    .claims;
    if claims.purpose != "oidc" || q.get("state") != Some(&claims.pending.state) {
        return Err(Error::unauthorized("sign-in state does not match; start again"));
    }
    let code = q.get("code").ok_or_else(|| Error::unauthorized("no authorization code"))?;
    let identity = oidc.finish(code, &claims.pending).await?;

    let account = match state
        .repos
        .by_external_subject(crate::db::AUTH_PROVIDER_OIDC, &identity.subject)
        .await?
    {
        Some(a) => a,
        None => match provision(&state, oidc.config(), &identity).await {
            Ok(a) => a,
            Err(message) => {
                tracing::info!(subject = %identity.subject, "oidc sign-in refused: {message}");
                return Ok(page(StatusCode::UNAUTHORIZED, &message));
            }
        },
    };
    // Groups are replaced at every sign-in, so a group removed at the IdP
    // stops counting from the next session.
    state.repos.set_groups(account.id, &identity.groups).await?;
    tracing::info!(account = %account.id, groups = identity.groups.len(), "oidc sign-in");

    let session = session_response(&state, account.id, account.token_version)?;
    let mut response = page(StatusCode::OK, "Signed in. Opening OpsClaw…");
    // Carry the session cookie over, clear the pending one, and bounce to
    // the app from a same-site page (a Strict cookie set during a
    // cross-site redirect chain would not be sent on the next hop).
    for v in session.headers().get_all(header::SET_COOKIE) {
        response.headers_mut().append(header::SET_COOKIE, v.clone());
    }
    response.headers_mut().append(
        header::SET_COOKIE,
        pending_cookie("", state.config.http.cookies_secure, 0).parse().expect("static cookie"),
    );
    response.headers_mut().insert(header::REFRESH, "0; url=/app".parse().expect("static header"));
    Ok(response)
}

/// Create an account for a first-time SSO sign-in, if allowed.
async fn provision(
    state: &AppState,
    cfg: &crate::config::OidcCfg,
    identity: &crate::http::oidc::OidcIdentity,
) -> std::result::Result<Account, String> {
    if !cfg.auto_create {
        return Err(
            "No OpsClaw account is linked to your sign-in. Ask an OpsClaw admin to add you.".into(),
        );
    }
    let email = identity
        .email
        .as_deref()
        .map(str::to_ascii_lowercase)
        .ok_or("Your identity provider did not send a verified email address.")?;
    let domain = email.rsplit('@').next().unwrap_or_default();
    if !cfg.allowed_domains.is_empty()
        && !cfg.allowed_domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
    {
        return Err(format!("Accounts from {domain} cannot sign in here."));
    }
    match state.repos.by_email(&email).await {
        Ok(Some(_)) => {
            return Err(format!(
                "An account for {email} exists but is not linked to this sign-in. Ask an admin \
                 to link it."
            ));
        }
        Ok(None) => {}
        Err(e) => return Err(format!("account lookup failed: {e}")),
    }
    let account = Account {
        id: Uuid::new_v4(),
        email: email.clone(),
        display_name: identity.name.clone().unwrap_or_else(|| email.clone()),
        password_hash: crate::http::auth::NO_PASSWORD.to_string(),
        token_version: 0,
        created_at: Utc::now(),
        auth_provider: crate::db::AUTH_PROVIDER_OIDC.to_string(),
        external_subject: Some(identity.subject.clone()),
    };
    AccountRepo::insert(&*state.repos, &account)
        .await
        .map_err(|e| format!("account not created: {e}"))?;
    tracing::info!(account = %account.id, %email, "account created at first SSO sign-in");
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    struct Idp {
        server: MockServer,
        key: EncodingKey,
    }

    async fn idp() -> Idp {
        let server = MockServer::start().await;
        let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let der = private.to_pkcs1_der().unwrap();
        let key = EncodingKey::from_rsa_der(der.as_bytes());
        let public = private.to_public_key();
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [{
                "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
                "n": b64(&public.n().to_bytes_be()), "e": b64(&public.e().to_bytes_be()),
            }]})))
            .mount(&server)
            .await;
        Idp { server, key }
    }

    impl Idp {
        async fn will_issue(&self, claims: serde_json::Value) {
            let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("k1".into());
            let token = encode(&header, &claims, &self.key).unwrap();
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({ "id_token": token })),
                )
                .mount(&self.server)
                .await;
        }
    }

    fn state_for(idp: &Idp, auto_create: bool) -> AppState {
        let issuer = idp.server.uri();
        let config: crate::config::Config = toml::from_str(&format!(
            r#"
            [auth]
            provider = "oidc"
            [auth.oidc]
            issuer = "{issuer}"
            client_id = "opsclaw"
            redirect_url = "http://localhost:8484/api/auth/oidc/callback"
            groups_claim = "roles"
            auto_create = {auto_create}
            allowed_domains = ["acme.com"]
            "#
        ))
        .unwrap();
        let mut state = AppState::fake_with_config(config.clone());
        state.oidc = Some(std::sync::Arc::new(
            crate::http::oidc::OidcClient::new(config.auth.oidc.as_ref().unwrap(), None).unwrap(),
        ));
        state
    }

    fn pending_header(state: &AppState, nonce: &str) -> HeaderMap {
        let claims = PendingClaims {
            purpose: "oidc".into(),
            exp: (Utc::now().timestamp() + 300) as usize,
            pending: Pending { state: "st".into(), nonce: nonce.into(), verifier: "v".repeat(43) },
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
        )
        .unwrap();
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, format!("{PENDING_COOKIE}={token}").parse().unwrap());
        h
    }

    fn query(state: &str) -> Query<HashMap<String, String>> {
        Query(
            [("code".to_string(), "c".to_string()), ("state".to_string(), state.to_string())]
                .into(),
        )
    }

    fn claims(idp: &Idp, nonce: &str) -> serde_json::Value {
        json!({
            "iss": idp.server.uri(), "aud": "opsclaw", "sub": "user-1", "nonce": nonce,
            "exp": Utc::now().timestamp() + 600, "iat": Utc::now().timestamp(),
            "email": "Jane@acme.com", "name": "Jane", "roles": ["oncall"],
        })
    }

    #[tokio::test]
    async fn start_redirects_to_the_idp_with_pkce() {
        let idp = idp().await;
        let state = state_for(&idp, true);
        let resp = start(State(state), ClientAddr(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = resp.headers()[header::LOCATION].to_str().unwrap();
        assert!(loc.starts_with(&format!("{}/authorize?", idp.server.uri())), "{loc}");
        assert!(loc.contains("code_challenge_method=S256") && loc.contains("nonce="), "{loc}");
        let cookie = resp.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.contains("SameSite=Lax") && cookie.contains("HttpOnly"), "{cookie}");
    }

    #[tokio::test]
    async fn first_sign_in_creates_the_account_and_stores_groups() {
        let idp = idp().await;
        idp.will_issue(claims(&idp, "n1")).await;
        let state = state_for(&idp, true);
        let resp = callback(
            State(state.clone()),
            ClientAddr(None),
            pending_header(&state, "n1"),
            query("st"),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cookies: Vec<_> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(
            cookies
                .iter()
                .any(|c| c.starts_with("opsclaw_session=") && c.contains("Max-Age=28800")),
            "{cookies:?}"
        );
        let account = state
            .repos
            .by_external_subject(crate::db::AUTH_PROVIDER_OIDC, "user-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.email, "jane@acme.com");
        assert_eq!(state.repos.groups(account.id).await.unwrap(), vec!["oncall".to_string()]);
    }

    #[tokio::test]
    async fn bad_state_wrong_nonce_and_no_auto_create_are_refused() {
        let idp = idp().await;
        idp.will_issue(claims(&idp, "n1")).await;
        let state = state_for(&idp, true);
        assert!(
            callback(
                State(state.clone()),
                ClientAddr(None),
                pending_header(&state, "n1"),
                query("forged")
            )
            .await
            .is_err()
        );
        assert!(
            callback(
                State(state.clone()),
                ClientAddr(None),
                pending_header(&state, "other"),
                query("st")
            )
            .await
            .is_err()
        );

        let state = state_for(&idp, false);
        let resp = callback(
            State(state.clone()),
            ClientAddr(None),
            pending_header(&state, "n1"),
            query("st"),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            state
                .repos
                .by_external_subject(crate::db::AUTH_PROVIDER_OIDC, "user-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_token_from_another_audience_is_refused() {
        let idp = idp().await;
        let mut c = claims(&idp, "n1");
        c["aud"] = json!("someone-else");
        idp.will_issue(c).await;
        let state = state_for(&idp, true);
        assert!(
            callback(
                State(state.clone()),
                ClientAddr(None),
                pending_header(&state, "n1"),
                query("st")
            )
            .await
            .is_err()
        );
    }
}
