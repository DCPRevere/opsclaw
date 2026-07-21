//! Web-push subscription storage (push channel task — see `db::repo`'s
//! module doc for the trait's provenance; no Wave 0 analog).

use async_trait::async_trait;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::Result;
use crate::db::PushSubscription;

fn row_to_sub(row: &SqliteRow) -> PushSubscription {
    PushSubscription {
        endpoint: row.get("endpoint"),
        account_id: Uuid::parse_str(row.get("account_id")).expect("stored uuid"),
        p256dh: row.get("p256dh"),
        auth: row.get("auth"),
        created_at: row.get::<String, _>("created_at").parse().expect("stored rfc3339"),
    }
}

#[async_trait]
impl crate::db::PushSubscriptionRepo for SqliteDb {
    async fn upsert_push_subscription(&self, sub: &PushSubscription) -> Result<()> {
        sqlx::query(
            "INSERT INTO push_subscriptions (endpoint, account_id, p256dh, auth, created_at)
             VALUES (?,?,?,?,?)
             ON CONFLICT (endpoint) DO UPDATE SET
                account_id = excluded.account_id,
                p256dh = excluded.p256dh,
                auth = excluded.auth",
        )
        .bind(&sub.endpoint)
        .bind(sub.account_id.to_string())
        .bind(&sub.p256dh)
        .bind(&sub.auth)
        .bind(sub.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_push_subscriptions(&self) -> Result<Vec<PushSubscription>> {
        let rows = sqlx::query("SELECT * FROM push_subscriptions ORDER BY created_at")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_sub).collect())
    }

    async fn delete_push_subscription(&self, endpoint: &str) -> Result<()> {
        sqlx::query("DELETE FROM push_subscriptions WHERE endpoint = ?")
            .bind(endpoint)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
