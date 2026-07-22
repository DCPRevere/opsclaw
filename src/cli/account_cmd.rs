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
}

/// Create an operator account. The password arrives already-acquired (the
/// binary layer prompts hidden, same rule as `secret set`: never argv).
pub async fn create(
    db: &Db,
    email: &str,
    display_name: &str,
    password: &str,
) -> Result<CreateOutcome> {
    let email = email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(crate::Error::validation(format!("{email:?} is not a usable email address")));
    }
    if password.len() < 12 {
        return Err(crate::Error::validation(
            "password must be at least 12 characters (it guards a daemon that can act on \
             production systems)",
        ));
    }
    if db.repos().by_email(&email).await?.is_some() {
        return Err(crate::Error::validation(format!("an account for {email} already exists")));
    }
    let account = Account {
        id: Uuid::new_v4(),
        email: email.clone(),
        display_name: display_name.trim().to_string(),
        password_hash: auth::hash_password(password)?,
        token_version: 0,
        created_at: Utc::now(),
    };
    AccountRepo::insert(&*db.repos(), &account).await?;
    Ok(CreateOutcome { id: account.id, email, display_name: account.display_name })
}

/// Registered operator accounts (id, email, display name — never hashes).
pub async fn list(db: &Db) -> Result<Vec<CreateOutcome>> {
    Ok(AccountRepo::list(&*db.repos())
        .await?
        .into_iter()
        .map(|a| CreateOutcome { id: a.id, email: a.email, display_name: a.display_name })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_hashes_and_lists() {
        let db = Db::fake();
        let out = create(&db, "OPS@example.com", "dcp", "a-long-enough-password").await.unwrap();
        assert_eq!(out.email, "ops@example.com", "email is normalized");

        let stored = db.repos().by_email("ops@example.com").await.unwrap().unwrap();
        assert_ne!(stored.password_hash, "a-long-enough-password", "never plaintext");
        assert!(auth::verify_password("a-long-enough-password", &stored.password_hash).unwrap());

        assert_eq!(list(&db).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refuses_short_password_bad_email_and_duplicates() {
        let db = Db::fake();
        assert!(create(&db, "ops@example.com", "d", "short").await.is_err());
        assert!(create(&db, "not-an-email", "d", "a-long-enough-password").await.is_err());
        create(&db, "ops@example.com", "d", "a-long-enough-password").await.unwrap();
        let err = create(&db, "ops@example.com", "d", "a-long-enough-password").await.unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }
}
