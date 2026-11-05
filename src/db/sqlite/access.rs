use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::Result;
use crate::access::{Elevation, ElevationState, Label};

fn json<T>(r: serde_json::Result<T>) -> Result<T> {
    r.map_err(|e| crate::Error::Other(format!("access row json: {e}")))
}

fn row_to_elevation(row: &SqliteRow) -> Elevation {
    Elevation {
        id: Uuid::parse_str(row.get("id")).expect("stored uuid"),
        account: Uuid::parse_str(row.get("account_id")).expect("stored uuid"),
        scope: row.get("scope"),
        class: row.get("class"),
        reason: row.get("reason"),
        requested_at: row.get::<String, _>("requested_at").parse().expect("stored rfc3339"),
        expires_at: row.get::<String, _>("expires_at").parse().expect("stored rfc3339"),
        state: ElevationState::parse(row.get("state")).expect("stored elevation state"),
        decided_by: row
            .get::<Option<String>, _>("decided_by")
            .map(|s| Uuid::parse_str(&s).expect("stored uuid")),
    }
}

#[async_trait]
impl crate::db::AccessRepo for SqliteDb {
    async fn set_groups(&self, account: Uuid, groups: &[String]) -> Result<()> {
        sqlx::query(
            "INSERT INTO account_groups (account_id, groups, updated_at) VALUES (?,?,?)
             ON CONFLICT (account_id) DO UPDATE SET groups = excluded.groups,
                                                   updated_at = excluded.updated_at",
        )
        .bind(account.to_string())
        .bind(json(serde_json::to_string(groups))?)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn groups(&self, account: Uuid) -> Result<Vec<String>> {
        let row = sqlx::query("SELECT groups FROM account_groups WHERE account_id = ?")
            .bind(account.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some(r) => json(serde_json::from_str(r.get("groups")))?,
            None => Vec::new(),
        })
    }

    async fn insert_elevation(&self, e: &Elevation) -> Result<()> {
        sqlx::query(
            "INSERT INTO access_elevations (id, account_id, scope, class, reason, requested_at,
                                            expires_at, state, decided_by)
             VALUES (?,?,?,?,?,?,?,?,?)",
        )
        .bind(e.id.to_string())
        .bind(e.account.to_string())
        .bind(&e.scope)
        .bind(&e.class)
        .bind(&e.reason)
        .bind(e.requested_at.to_rfc3339())
        .bind(e.expires_at.to_rfc3339())
        .bind(e.state.as_str())
        .bind(e.decided_by.map(|d| d.to_string()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn elevation(&self, id: Uuid) -> Result<Option<Elevation>> {
        let row = sqlx::query("SELECT * FROM access_elevations WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_elevation))
    }

    async fn elevations_for(&self, account: Uuid) -> Result<Vec<Elevation>> {
        let rows = sqlx::query(
            "SELECT * FROM access_elevations WHERE account_id = ? ORDER BY requested_at DESC",
        )
        .bind(account.to_string())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_elevation).collect())
    }

    async fn list_elevations(&self) -> Result<Vec<Elevation>> {
        let rows = sqlx::query("SELECT * FROM access_elevations ORDER BY requested_at DESC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_elevation).collect())
    }

    async fn decide_elevation(
        &self,
        id: Uuid,
        state: ElevationState,
        decided_by: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let res = sqlx::query(
            "UPDATE access_elevations
                SET state = ?, decided_by = COALESCE(?, decided_by),
                    expires_at = COALESCE(?, expires_at)
              WHERE id = ?",
        )
        .bind(state.as_str())
        .bind(decided_by.map(|d| d.to_string()))
        .bind(expires_at.map(|t| t.to_rfc3339()))
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(crate::Error::NotFound(format!("elevation {id}")));
        }
        Ok(())
    }

    async fn add_labels(&self, kind: &str, id: &str, labels: &[Label]) -> Result<()> {
        let mut all = self.labels(kind, id).await?;
        all.extend(labels.iter().cloned());
        all.sort();
        all.dedup();
        sqlx::query(
            "INSERT INTO finding_labels (kind, id, labels) VALUES (?,?,?)
             ON CONFLICT (kind, id) DO UPDATE SET labels = excluded.labels",
        )
        .bind(kind)
        .bind(id)
        .bind(json(serde_json::to_string(&all))?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn labels(&self, kind: &str, id: &str) -> Result<Vec<Label>> {
        let row = sqlx::query("SELECT labels FROM finding_labels WHERE kind = ? AND id = ?")
            .bind(kind)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some(r) => json(serde_json::from_str(r.get("labels")))?,
            None => Vec::new(),
        })
    }

    async fn set_restricted(&self, kind: &str, id: &str, to: Option<&[String]>) -> Result<()> {
        let to = json(to.map(serde_json::to_string).transpose())?;
        sqlx::query(
            "INSERT INTO finding_labels (kind, id, labels, restricted_to) VALUES (?,?,'[]',?)
             ON CONFLICT (kind, id) DO UPDATE SET restricted_to = excluded.restricted_to",
        )
        .bind(kind)
        .bind(id)
        .bind(to)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn restricted(&self, kind: &str, id: &str) -> Result<Option<Vec<String>>> {
        let row = sqlx::query("SELECT restricted_to FROM finding_labels WHERE kind = ? AND id = ?")
            .bind(kind)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row.and_then(|r| r.get::<Option<String>, _>("restricted_to")) {
            Some(s) => Some(json(serde_json::from_str(&s))?),
            None => None,
        })
    }
}
