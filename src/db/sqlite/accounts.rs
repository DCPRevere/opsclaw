use async_trait::async_trait;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::Result;
use crate::db::Account;

fn row_to_account(row: &SqliteRow) -> Account {
    Account {
        id: Uuid::parse_str(row.get("id")).expect("stored uuid"),
        email: row.get("email"),
        display_name: row.get("display_name"),
        password_hash: row.get("password_hash"),
        token_version: row.get("token_version"),
        created_at: row.get::<String, _>("created_at").parse().expect("stored rfc3339"),
        auth_provider: row.get("auth_provider"),
        external_subject: row.get("external_subject"),
    }
}

#[async_trait]
impl crate::db::AccountRepo for SqliteDb {
    async fn insert(&self, account: &Account) -> Result<()> {
        sqlx::query(
            "INSERT INTO accounts (id, email, display_name, password_hash, token_version,
                                   created_at, auth_provider, external_subject)
             VALUES (?,?,?,?,?,?,?,?)",
        )
        .bind(account.id.to_string())
        .bind(&account.email)
        .bind(&account.display_name)
        .bind(&account.password_hash)
        .bind(account.token_version)
        .bind(account.created_at.to_rfc3339())
        .bind(&account.auth_provider)
        .bind(&account.external_subject)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn by_email(&self, email: &str) -> Result<Option<Account>> {
        let row = sqlx::query("SELECT * FROM accounts WHERE email = ?")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_account))
    }

    async fn by_external_subject(&self, provider: &str, subject: &str) -> Result<Option<Account>> {
        let row =
            sqlx::query("SELECT * FROM accounts WHERE auth_provider = ? AND external_subject = ?")
                .bind(provider)
                .bind(subject)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.as_ref().map(row_to_account))
    }

    async fn set_password_hash(&self, id: Uuid, password_hash: &str) -> Result<()> {
        sqlx::query("UPDATE accounts SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn link_external_subject(
        &self,
        id: Uuid,
        provider: &str,
        subject: &str,
        password_hash: Option<&str>,
    ) -> Result<()> {
        // The partial unique index on (auth_provider, external_subject) is
        // what actually enforces one-operator-per-identity; translate its
        // violation into a Conflict rather than a raw 500.
        //
        // COALESCE keeps the existing hash when the caller passes None, so
        // linking does not disarm the account's current way in.
        sqlx::query(
            "UPDATE accounts
                SET auth_provider = ?, external_subject = ?,
                    password_hash = COALESCE(?, password_hash)
             WHERE id = ?",
        )
        .bind(provider)
        .bind(subject)
        .bind(password_hash)
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
                crate::Error::Conflict(format!(
                    "another account is already linked to {provider} subject {subject}"
                ))
            } else {
                e.into()
            }
        })?;
        Ok(())
    }

    async fn by_id(&self, id: Uuid) -> Result<Option<Account>> {
        let row = sqlx::query("SELECT * FROM accounts WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_account))
    }

    async fn bump_token_version(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE accounts SET token_version = token_version + 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<Account>> {
        let rows =
            sqlx::query("SELECT * FROM accounts ORDER BY created_at").fetch_all(&self.pool).await?;
        Ok(rows.iter().map(row_to_account).collect())
    }
}
