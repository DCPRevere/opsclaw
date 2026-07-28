//! `opsclaw-cli account create/list` — the first-boot account bootstrap the
//! invite flow's own doc promises ("the FIRST account is created by the
//! local CLI directly via `AccountRepo::insert`") but nothing implemented
//! until now: with zero accounts there is no way to sign in to the web UI,
//! and `POST /api/invites` is `Authed`-gated, so the system was
//! unenterable. Local mode only — opens the daemon's SQLite directly, no
//! HTTP. Every account after the first should use the invite flow so
//! issuance is attributed.

use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::Result;
use crate::db::{Account, AccountRepo, Db};
use crate::http::auth;

#[derive(Debug, Serialize)]
pub struct CreateOutcome {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    /// Which provider this account signs in through. Carried so
    /// `account list` can answer the one question the provider flip depends
    /// on — "is every operator linked yet?" — which was otherwise
    /// unanswerable without opening the database by hand.
    pub auth_provider: String,
    pub external_subject: Option<String>,
}

fn outcome(
    id: Uuid,
    email: String,
    display_name: String,
    auth_provider: &str,
    external_subject: Option<&str>,
) -> CreateOutcome {
    CreateOutcome {
        id,
        email,
        display_name,
        auth_provider: auth_provider.to_string(),
        external_subject: external_subject.map(str::to_string),
    }
}

/// How the new account will prove its identity at login.
pub enum Credential<'a> {
    /// An argon2 password. Arrives already-acquired (the binary layer
    /// prompts hidden, same rule as `secret set`: never argv).
    Password(&'a str),
    /// A Hanko subject id (`claims.subject`). The account gets no usable
    /// password hash at all — the sentinel `auth::NO_PASSWORD`, which
    /// `verify_password` refuses.
    HankoSubject(&'a str),
}

/// Create an operator account.
pub async fn create(
    db: &Db,
    email: &str,
    display_name: &str,
    credential: Credential<'_>,
) -> Result<CreateOutcome> {
    let email = email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(crate::Error::validation(format!("{email:?} is not a usable email address")));
    }
    let (password_hash, auth_provider, external_subject) = match credential {
        Credential::Password(password) => {
            if password.len() < 12 {
                return Err(crate::Error::validation(
                    "password must be at least 12 characters (it guards a daemon that can act on \
                     production systems)",
                ));
            }
            (auth::hash_password(password)?, crate::db::AUTH_PROVIDER_LOCAL, None)
        }
        Credential::HankoSubject(subject) => {
            let subject = subject.trim();
            if subject.is_empty() {
                return Err(crate::Error::validation(
                    "the hanko subject must not be empty — it is the user id shown in the Hanko \
                     console, and it is what the account links to",
                ));
            }
            if db
                .repos()
                .by_external_subject(crate::db::AUTH_PROVIDER_HANKO, subject)
                .await?
                .is_some()
            {
                return Err(crate::Error::validation(format!(
                    "an account is already linked to hanko subject {subject}"
                )));
            }
            (
                auth::NO_PASSWORD.to_string(),
                crate::db::AUTH_PROVIDER_HANKO,
                Some(subject.to_string()),
            )
        }
    };
    if db.repos().by_email(&email).await?.is_some() {
        return Err(crate::Error::validation(format!("an account for {email} already exists")));
    }
    let account = Account {
        id: Uuid::new_v4(),
        email: email.clone(),
        display_name: display_name.trim().to_string(),
        password_hash,
        token_version: 0,
        created_at: Utc::now(),
        auth_provider: auth_provider.to_string(),
        external_subject,
    };
    AccountRepo::insert(&*db.repos(), &account).await?;
    Ok(outcome(
        account.id,
        email,
        account.display_name,
        auth_provider,
        account.external_subject.as_deref(),
    ))
}

/// Link an EXISTING operator account to a Hanko subject.
///
/// This is the pre-flip migration step. Operator rows created under the
/// local provider carry no external subject, and the hanko exchange route
/// resolves accounts by subject alone — so without this, switching
/// `auth.provider` to hanko locks out every existing operator.
/// Deliberately usable while the daemon is still on `local`: linking is
/// preparation, done before the switch, not after it.
///
/// The password is KEPT by default. That is the whole point of the
/// ordering: linking happens while the daemon is still on `local`, where
/// the hanko route refuses every request, so an account whose password was
/// dropped at link time could sign in by neither method until the flip
/// completed — a self-inflicted outage lasting as long as the rollout.
/// Under `hanko` the surviving hash is unreachable anyway (`/api/login` is
/// gated on the handler), so keeping it costs no security and is what makes
/// a rollback a config edit rather than a database restore.
///
/// `drop_password` forces the sentinel for a deployment that wants the hash
/// gone regardless.
pub async fn link_hanko(
    db: &Db,
    email: &str,
    subject: &str,
    drop_password: bool,
) -> Result<CreateOutcome> {
    let email = email.trim().to_ascii_lowercase();
    let subject = subject.trim();
    if subject.is_empty() {
        return Err(crate::Error::validation(
            "the hanko subject must not be empty — it is the user id shown in the Hanko console",
        ));
    }
    let account = db
        .repos()
        .by_email(&email)
        .await?
        .ok_or_else(|| crate::Error::NotFound(format!("account for {email}")))?;
    AccountRepo::link_external_subject(
        &*db.repos(),
        account.id,
        crate::db::AUTH_PROVIDER_HANKO,
        subject,
        drop_password.then_some(auth::NO_PASSWORD),
    )
    .await?;
    Ok(outcome(
        account.id,
        email,
        account.display_name,
        crate::db::AUTH_PROVIDER_HANKO,
        Some(subject),
    ))
}

/// Set an operator's password. The way back off an external provider, and
/// the way to recover an account whose password was dropped at link time.
/// Refuses to run while a non-local provider is configured only at the
/// caller's discretion — the binary layer decides, since a password set
/// while on `hanko` is legitimate preparation for rolling back.
pub async fn set_password(db: &Db, email: &str, password: &str) -> Result<CreateOutcome> {
    let email = email.trim().to_ascii_lowercase();
    if password.len() < 12 {
        return Err(crate::Error::validation(
            "password must be at least 12 characters (it guards a daemon that can act on \
             production systems)",
        ));
    }
    let account = db
        .repos()
        .by_email(&email)
        .await?
        .ok_or_else(|| crate::Error::NotFound(format!("account for {email}")))?;
    AccountRepo::set_password_hash(&*db.repos(), account.id, &auth::hash_password(password)?)
        .await?;
    Ok(outcome(
        account.id,
        email,
        account.display_name,
        &account.auth_provider,
        account.external_subject.as_deref(),
    ))
}

/// Revoke every outstanding session for an operator: bump `token_version`
/// (which invalidates every web session cookie) and delete every `ops_` CLI
/// token.
///
/// This is the offboarding path, and it matters more under an external
/// provider than under local passwords: deactivating a user at the identity
/// provider does NOT reach this daemon. An issued session cookie stays valid
/// for up to `SESSION_TTL_DAYS`, and CLI tokens have no expiry at all — they
/// live outside the `token_version` scheme entirely, so nothing but an
/// explicit revoke removes them.
pub async fn revoke_sessions(db: &Db, email: &str) -> Result<usize> {
    let email = email.trim().to_ascii_lowercase();
    let account = db
        .repos()
        .by_email(&email)
        .await?
        .ok_or_else(|| crate::Error::NotFound(format!("account for {email}")))?;
    AccountRepo::bump_token_version(&*db.repos(), account.id).await?;
    let tokens = db.repos().list_cli_tokens(account.id).await?;
    for t in &tokens {
        db.repos().revoke_cli_token(account.id, t.id).await?;
    }
    Ok(tokens.len())
}

/// Registered operator accounts (id, email, display name — never hashes).
pub async fn list(db: &Db) -> Result<Vec<CreateOutcome>> {
    Ok(AccountRepo::list(&*db.repos())
        .await?
        .into_iter()
        .map(|a| {
            outcome(a.id, a.email, a.display_name, &a.auth_provider, a.external_subject.as_deref())
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_hashes_and_lists() {
        let db = Db::fake();
        let out =
            create(&db, "OPS@example.com", "dcp", Credential::Password("a-long-enough-password"))
                .await
                .unwrap();
        assert_eq!(out.email, "ops@example.com", "email is normalized");

        let stored = db.repos().by_email("ops@example.com").await.unwrap().unwrap();
        assert_ne!(stored.password_hash, "a-long-enough-password", "never plaintext");
        assert!(auth::verify_password("a-long-enough-password", &stored.password_hash).unwrap());

        assert_eq!(list(&db).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refuses_short_password_bad_email_and_duplicates() {
        let db = Db::fake();
        assert!(create(&db, "ops@example.com", "d", Credential::Password("short")).await.is_err());
        assert!(
            create(&db, "not-an-email", "d", Credential::Password("a-long-enough-password"))
                .await
                .is_err()
        );
        create(&db, "ops@example.com", "d", Credential::Password("a-long-enough-password"))
            .await
            .unwrap();
        let err =
            create(&db, "ops@example.com", "d", Credential::Password("a-long-enough-password"))
                .await
                .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    /// The lockout regression. Linking runs while the daemon is still on
    /// `local`, where the hanko route refuses everything — so if linking
    /// dropped the password, the operator could sign in by NEITHER method
    /// until the flip completed.
    #[tokio::test]
    async fn linking_keeps_the_password_so_the_operator_is_never_locked_out() {
        let db = Db::fake();
        create(&db, "ops@example.com", "d", Credential::Password("a-long-enough-password"))
            .await
            .unwrap();
        let out = link_hanko(&db, "ops@example.com", "sub-1", false).await.unwrap();
        assert_eq!(out.auth_provider, crate::db::AUTH_PROVIDER_HANKO);
        assert_eq!(out.external_subject.as_deref(), Some("sub-1"));

        let stored = db.repos().by_email("ops@example.com").await.unwrap().unwrap();
        assert!(
            auth::verify_password("a-long-enough-password", &stored.password_hash).unwrap(),
            "the password must still work until the provider actually changes"
        );
        // And the identity resolves, so the flip will find them.
        assert!(
            db.repos()
                .by_external_subject(crate::db::AUTH_PROVIDER_HANKO, "sub-1")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn drop_password_is_opt_in_and_set_password_recovers_it() {
        let db = Db::fake();
        create(&db, "ops@example.com", "d", Credential::Password("a-long-enough-password"))
            .await
            .unwrap();
        link_hanko(&db, "ops@example.com", "sub-1", true).await.unwrap();
        let stored = db.repos().by_email("ops@example.com").await.unwrap().unwrap();
        assert_eq!(stored.password_hash, auth::NO_PASSWORD);
        assert!(!auth::verify_password("a-long-enough-password", &stored.password_hash).unwrap());

        // The recovery path: this is what makes rolling back off an external
        // provider a config edit rather than a database restore.
        set_password(&db, "ops@example.com", "another-long-password").await.unwrap();
        let stored = db.repos().by_email("ops@example.com").await.unwrap().unwrap();
        assert!(auth::verify_password("another-long-password", &stored.password_hash).unwrap());
        // Linkage survives a password reset — the two are independent.
        assert_eq!(stored.external_subject.as_deref(), Some("sub-1"));
    }

    #[tokio::test]
    async fn set_password_enforces_the_length_rule_and_a_known_account() {
        let db = Db::fake();
        create(&db, "ops@example.com", "d", Credential::Password("a-long-enough-password"))
            .await
            .unwrap();
        assert!(set_password(&db, "ops@example.com", "short").await.is_err());
        assert!(set_password(&db, "nobody@example.com", "a-long-enough-password").await.is_err());
    }

    #[tokio::test]
    async fn list_reports_linkage_so_a_flip_can_be_checked() {
        let db = Db::fake();
        create(&db, "linked@example.com", "d", Credential::Password("a-long-enough-password"))
            .await
            .unwrap();
        create(&db, "plain@example.com", "d", Credential::Password("a-long-enough-password"))
            .await
            .unwrap();
        link_hanko(&db, "linked@example.com", "sub-1", false).await.unwrap();

        let all = list(&db).await.unwrap();
        let unlinked: Vec<_> =
            all.iter().filter(|a| a.external_subject.is_none()).map(|a| &a.email).collect();
        assert_eq!(unlinked, vec!["plain@example.com"], "the flip precondition must be visible");
    }
}
