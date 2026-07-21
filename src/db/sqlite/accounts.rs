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
    }
}

#[async_trait]
impl crate::db::AccountRepo for SqliteDb {
    async fn insert(&self, account: &Account) -> Result<()> {
        sqlx::query(
            "INSERT INTO accounts (id, email, display_name, password_hash, token_version, created_at)
             VALUES (?,?,?,?,?,?)",
        )
        .bind(account.id.to_string())
        .bind(&account.email)
        .bind(&account.display_name)
        .bind(&account.password_hash)
        .bind(account.token_version)
        .bind(account.created_at.to_rfc3339())
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
