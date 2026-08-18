//! Local teammate-invite management over the same repository as the daemon.

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::Result;
use crate::db::{AccountRepo, AllRepos, Invite, InviteRepo};

pub async fn list(repos: &dyn AllRepos) -> Result<Vec<Invite>> {
    InviteRepo::list_open_invites(repos, Utc::now()).await
}

pub async fn create(repos: &dyn AllRepos, as_email: Option<&str>) -> Result<Invite> {
    let accounts = AccountRepo::list(repos).await?;
    let issuer = match as_email {
        Some(email) => accounts
            .iter()
            .find(|account| account.email.eq_ignore_ascii_case(email))
            .map(|account| account.id)
            .ok_or_else(|| crate::Error::NotFound(format!("operator {email:?}")))?,
        None if accounts.len() == 1 => accounts[0].id,
        None => {
            return Err(crate::Error::validation(
                "cannot infer invite issuer — pass --as <operator-email>",
            ));
        }
    };
    let code = crate::http::cli_auth::challenge_for(&Uuid::new_v4().to_string())[..16].to_string();
    let now = Utc::now();
    let invite =
        Invite { code, issued_by: issuer, created_at: now, expires_at: now + Duration::days(7) };
    InviteRepo::create_invite(repos, &invite).await?;
    Ok(invite)
}

pub async fn revoke(repos: &dyn AllRepos, code: &str) -> Result<bool> {
    InviteRepo::revoke_invite(repos, code).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AUTH_PROVIDER_LOCAL, Account, AccountRepo, Db};

    #[tokio::test]
    async fn create_list_and_revoke_use_the_local_repository() {
        let db = Db::fake();
        let account = Account {
            id: Uuid::new_v4(),
            email: "ops@example.com".into(),
            display_name: "ops".into(),
            password_hash: "not-used".into(),
            token_version: 0,
            created_at: Utc::now(),
            auth_provider: AUTH_PROVIDER_LOCAL.into(),
            external_subject: None,
        };
        AccountRepo::insert(db.repos().as_ref(), &account).await.unwrap();

        let invite = create(db.repos().as_ref(), None).await.unwrap();
        assert_eq!(invite.issued_by, account.id);
        assert_eq!(list(db.repos().as_ref()).await.unwrap().len(), 1);
        assert!(revoke(db.repos().as_ref(), &invite.code).await.unwrap());
        assert!(list(db.repos().as_ref()).await.unwrap().is_empty());
    }
}
