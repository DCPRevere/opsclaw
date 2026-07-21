use async_trait::async_trait;

use super::InMemoryDb;
use crate::Result;
use crate::audit::AuditRecord;
use crate::error::Error;

#[async_trait]
impl crate::db::AuditRepo for InMemoryDb {
    async fn append(&self, record: &AuditRecord) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        let expected = store.audit_log.last().map(|r| r.seq).unwrap_or(0) + 1;
        if record.seq != expected {
            return Err(Error::Conflict(format!(
                "audit append: seq {} is not last+1 (expected {expected})",
                record.seq
            )));
        }
        store.audit_log.push(record.clone());
        Ok(())
    }

    async fn last(&self) -> Result<Option<AuditRecord>> {
        let store = self.store.lock().unwrap();
        Ok(store.audit_log.last().cloned())
    }

    async fn range(&self, from_seq: i64, limit: i64) -> Result<Vec<AuditRecord>> {
        let store = self.store.lock().unwrap();
        Ok(store
            .audit_log
            .iter()
            .filter(|r| r.seq >= from_seq)
            .take(limit.max(0) as usize)
            .cloned()
            .collect())
    }
}
