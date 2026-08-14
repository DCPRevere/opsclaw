//! `opsclaw-cli tokens list|revoke` — the `ops_` CLI sessions.
//!
//! `TokenRepo` and `/api/cli-tokens` have always existed; no CLI command
//! did. That matters more than a missing convenience, because CHANGELOG.md
//! tells operators that **CLI tokens never expire** and that revoking them
//! is the step that actually ends someone's access — deactivating a user at
//! the identity provider does not reach this daemon. The documented
//! offboarding procedure had no command behind it outside the web UI.
//!
//! Scoped per account by construction: `TokenRepo::revoke_cli_token` takes
//! the account id and returns whether a row was removed, so one operator's
//! session can never revoke another's. That scoping is enforced in the repo,
//! not here — this module only supplies the account.
//!
//! Metadata only. `CliToken` carries the device label, creation and
//! last-used times; the plaintext token was never stored and its hash is not
//! exposed by `list_cli_tokens`, so nothing printed here can be replayed.

use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

use crate::Result;
use crate::db::{AccountRepo, AllRepos, TokenRepo};

#[derive(Debug, Serialize)]
pub struct TokenView {
    pub id: Uuid,
    pub account: String,
    /// Device/host label supplied at mint time.
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Every CLI session for one operator, or for all of them when `email` is
/// `None` — offboarding asks "what does this person still hold?", and an
/// audit asks "what exists at all?".
pub async fn list(repos: &Arc<dyn AllRepos>, email: Option<&str>) -> Result<Vec<TokenView>> {
    let accounts = AccountRepo::list(&**repos).await?;
    let wanted: Vec<_> = match email {
        Some(e) => {
            let found: Vec<_> =
                accounts.iter().filter(|a| a.email.eq_ignore_ascii_case(e)).collect();
            if found.is_empty() {
                return Err(crate::Error::Config(format!(
                    "no operator account {e:?}. Known: {}",
                    accounts.iter().map(|a| a.email.as_str()).collect::<Vec<_>>().join(", ")
                )));
            }
            found
        }
        None => accounts.iter().collect(),
    };

    let mut out = Vec::new();
    for account in wanted {
        for t in TokenRepo::list_cli_tokens(&**repos, account.id).await? {
            out.push(TokenView {
                id: t.id,
                account: account.email.clone(),
                name: t.name,
                created_at: t.created_at.to_rfc3339(),
                last_used_at: t.last_used_at.map(|d| d.to_rfc3339()),
            });
        }
    }
    Ok(out)
}

/// Revoke one token. `email` names the owner, so the repo's account scoping
/// applies; a token id belonging to someone else simply does not match.
pub async fn revoke(repos: &Arc<dyn AllRepos>, email: &str, token: Uuid) -> Result<bool> {
    let accounts = AccountRepo::list(&**repos).await?;
    let account =
        accounts.iter().find(|a| a.email.eq_ignore_ascii_case(email)).ok_or_else(|| {
            crate::Error::Config(format!(
                "no operator account {email:?}. Known: {}",
                accounts.iter().map(|a| a.email.as_str()).collect::<Vec<_>>().join(", ")
            ))
        })?;
    TokenRepo::revoke_cli_token(&**repos, account.id, token).await
}

pub fn render(views: &[TokenView]) -> String {
    if views.is_empty() {
        return "no CLI tokens.\n".to_string();
    }
    let mut out = String::new();
    for t in views {
        out.push_str(&format!("{}  {}\n", t.id, t.account));
        out.push_str(&format!("  label       {}\n", t.name));
        out.push_str(&format!("  created     {}\n", t.created_at));
        out.push_str(&format!(
            "  last used   {}\n",
            // "never" is the interesting case, not a gap to leave blank: a
            // token minted and never used is either a spare or a leak.
            t.last_used_at.as_deref().unwrap_or("never")
        ));
        out.push('\n');
    }
    out.push_str(
        "these do NOT expire. `opsclaw-cli tokens revoke --as <email> <id>` ends one;\n\
         `opsclaw-cli account revoke-sessions <email>` ends all of an operator's, plus\n\
         their web sessions.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::account_cmd::{Credential, create};
    use crate::db::{CliToken, Db};
    use chrono::Utc;

    async fn seed() -> (Db, Uuid) {
        let db = Db::connect("sqlite::memory:").await.unwrap();
        let account =
            create(&db, "ops@example.com", "Ops", Credential::Password("a-long-enough-password"))
                .await
                .unwrap();
        (db, account.id)
    }

    async fn mint(db: &Db, account: Uuid, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        TokenRepo::create_cli_token(
            &*db.repos(),
            CliToken { id, account, name: name.into(), created_at: Utc::now(), last_used_at: None },
            &format!("hash-of-{id}"),
        )
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn list_shows_sessions_and_names_them_by_owner() {
        let (db, account) = seed().await;
        let id = mint(&db, account, "jumpbox").await;

        let views = list(&db.repos(), None).await.unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].id, id);
        assert_eq!(views[0].account, "ops@example.com");

        let text = render(&views);
        assert!(text.contains("jumpbox"), "the device label is how you pick one: {text}");
        assert!(text.contains("never"), "an unused token must read as unused: {text}");
        assert!(text.contains("do NOT expire"), "the reason this command exists: {text}");
    }

    #[tokio::test]
    async fn revoking_ends_the_session() {
        let (db, account) = seed().await;
        let id = mint(&db, account, "laptop").await;
        assert!(revoke(&db.repos(), "ops@example.com", id).await.unwrap());
        assert!(list(&db.repos(), None).await.unwrap().is_empty());
        // Revoking again is a clean false, not an error — it is already gone.
        assert!(!revoke(&db.repos(), "ops@example.com", id).await.unwrap());
    }

    #[tokio::test]
    async fn one_account_cannot_revoke_anothers_token() {
        // The repo scopes by account; this pins that the CLI passes the
        // OWNER through rather than a lookup that would defeat it.
        let (db, account) = seed().await;
        let id = mint(&db, account, "jumpbox").await;
        create(&db, "other@example.com", "Other", Credential::Password("another-long-password"))
            .await
            .unwrap();

        assert!(
            !revoke(&db.repos(), "other@example.com", id).await.unwrap(),
            "a token id belonging to someone else must not match"
        );
        assert_eq!(list(&db.repos(), None).await.unwrap().len(), 1, "and it survives");
    }

    #[tokio::test]
    async fn an_unknown_email_is_an_error_that_lists_the_real_ones() {
        let (db, _) = seed().await;
        let err = list(&db.repos(), Some("nobody@example.com")).await.unwrap_err().to_string();
        assert!(err.contains("ops@example.com"), "{err}");
        assert!(revoke(&db.repos(), "nobody@example.com", Uuid::new_v4()).await.is_err());
    }

    #[tokio::test]
    async fn filtering_by_email_is_case_insensitive() {
        // An operator typing their own address should not have to match the
        // stored casing.
        let (db, account) = seed().await;
        mint(&db, account, "jumpbox").await;
        assert_eq!(list(&db.repos(), Some("OPS@Example.com")).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn no_tokens_says_so() {
        let (db, _) = seed().await;
        assert!(list(&db.repos(), None).await.unwrap().is_empty());
        assert!(render(&[]).contains("no CLI tokens"));
    }
}
