//! Read the durable shared chat transcript without starting an agent turn.

use serde::Serialize;

use crate::Result;
use crate::db::{ChatRepo, Db};

#[derive(Debug, Serialize)]
pub struct ChatHistoryRow {
    pub seq: i64,
    pub at: String,
    pub role: String,
    pub speaker: String,
    pub content: String,
}

pub async fn load(db: &Db, before: Option<i64>, limit: i64) -> Result<Vec<ChatHistoryRow>> {
    load_scoped(db, "operations", before, limit).await
}

pub async fn load_scoped(
    db: &Db,
    conversation: &str,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<ChatHistoryRow>> {
    crate::domain::ChatConversation::parse(conversation)?;
    let rows = match before {
        Some(seq) => ChatRepo::before_chat(db.repos().as_ref(), conversation, seq, limit).await?,
        None => ChatRepo::recent_chat(db.repos().as_ref(), conversation, limit).await?,
    };
    Ok(rows
        .into_iter()
        .map(|row| ChatHistoryRow {
            seq: row.seq,
            at: row.at.to_rfc3339(),
            role: row.role,
            speaker: row.speaker,
            content: row.content,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ChatRepo;

    #[tokio::test]
    async fn history_reads_the_latest_page_and_pages_back() {
        let db = Db::fake();
        for i in 0..4 {
            ChatRepo::append_chat(
                db.repos().as_ref(),
                "operations",
                None,
                chrono::Utc::now(),
                "user",
                "operator",
                &format!("m{i}"),
            )
            .await
            .unwrap();
        }
        let latest = load(&db, None, 2).await.unwrap();
        assert_eq!(latest.iter().map(|row| row.content.as_str()).collect::<Vec<_>>(), ["m2", "m3"]);
        let earlier = load(&db, Some(latest[0].seq), 2).await.unwrap();
        assert_eq!(
            earlier.iter().map(|row| row.content.as_str()).collect::<Vec<_>>(),
            ["m0", "m1"]
        );
    }
}
