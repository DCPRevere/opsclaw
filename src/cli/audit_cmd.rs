//! `opsclaw-cli audit verify` — walks the whole hash chain via
//! `db::AuditRepo::range` and `audit::chain::verify` (DESIGN.md §4: "`opsclaw
//! audit verify` re-walks the chain"). Paged rather than loading the whole
//! table into memory at once — an audit chain is append-only and grows
//! without bound over a deployment's life.

use serde::Serialize;

use crate::Result;
use crate::audit::chain::{self, ChainError};
use crate::db::Db;

const PAGE_SIZE: i64 = 500;

#[derive(Debug, Serialize)]
pub struct VerifyOutcome {
    pub ok: bool,
    pub records_verified: u64,
    pub failure: Option<String>,
}

/// `ChainError` has no `Display`/`thiserror` impl (audit/chain.rs) — this is
/// the CLI's own mapping to an operator-facing message, matching each
/// variant's meaning (bad hash / broken link / out-of-order seq).
fn describe(e: &ChainError) -> String {
    match e {
        ChainError::BadHash { seq } => {
            format!(
                "record at seq {seq} has a hash that doesn't match its own contents — tampered or corrupted"
            )
        }
        ChainError::BrokenLink { seq } => {
            format!(
                "record at seq {seq}'s prev_hash doesn't match the previous record's hash — chain broken"
            )
        }
        ChainError::BadSeq { seq, expected } => {
            format!("record out of order: got seq {seq}, expected {expected}")
        }
    }
}

/// Verify the whole chain starting at `from_seq` (1 = genesis, the normal
/// case; a nonzero start is for resuming a very large verify across
/// invocations, not exposed as a CLI flag today but kept as a parameter
/// since `AuditRepo::range`'s own signature is paging-shaped).
pub async fn verify(db: &Db, from_seq: i64) -> Result<VerifyOutcome> {
    let mut cursor = from_seq;
    let mut total_verified: u64 = 0;
    // `chain::verify` always treats the FIRST record in the slice it's given
    // as the chain start (seq must be 1, prev_hash must be GENESIS) — it has
    // no notion of "continuing from an earlier page". So every page after
    // the first is verified together WITH the previous page's last record
    // prepended, and the count is adjusted by -1 to not double-count that
    // carried-over record. This is simpler and less error-prone than
    // reimplementing verify()'s link/hash checks by hand for the cross-page
    // boundary (an earlier version of this function tried that and had a
    // bug where the boundary check ran but `chain::verify` on the new page
    // alone still independently — and wrongly — expected seq 1/GENESIS).
    let mut prev_tail: Option<crate::audit::AuditRecord> = None;

    loop {
        let page = db.repos().range(cursor, PAGE_SIZE).await?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();

        // verify_from validates this page as a continuation of the previous
        // page's (already-verified) tail — plain verify() would demand the
        // genesis record at the top of every page.
        let verify_result = chain::verify_from(prev_tail.as_ref(), page.iter());

        match verify_result {
            Ok(count) => total_verified += count,
            Err(e) => {
                return Ok(VerifyOutcome {
                    ok: false,
                    records_verified: total_verified,
                    failure: Some(describe(&e)),
                });
            }
        }

        prev_tail = page.into_iter().last();
        cursor = prev_tail.as_ref().map(|r| r.seq + 1).unwrap_or(cursor);
        if (page_len as i64) < PAGE_SIZE {
            break;
        }
    }

    Ok(VerifyOutcome { ok: true, records_verified: total_verified, failure: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditOutcome, AuditRecord};
    use crate::domain::{FqTarget, Principal, RiskClass};
    use chrono::Utc;
    use uuid::Uuid;

    fn unsealed_record(seq: i64) -> AuditRecord {
        AuditRecord {
            id: Uuid::new_v4(),
            seq,
            ts: Utc::now(),
            principal: Principal::Operator { account: Uuid::new_v4() },
            fq_target: FqTarget::new("p", "e", "t").to_string(),
            tool: "ssh".into(),
            command: "uptime".into(),
            risk: RiskClass::Read,
            outcome: AuditOutcome::Executed,
            exit_code: Some(0),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    async fn seed_chain(db: &Db, n: i64) {
        let mut tail: Option<AuditRecord> = None;
        for seq in 1..=n {
            let sealed = chain::seal(unsealed_record(seq), tail.as_ref()).unwrap();
            db.repos().append(&sealed).await.unwrap();
            tail = Some(sealed);
        }
    }

    #[tokio::test]
    async fn empty_chain_verifies_trivially() {
        let db = Db::fake();
        let outcome = verify(&db, 1).await.unwrap();
        assert!(outcome.ok);
        assert_eq!(outcome.records_verified, 0);
    }

    #[tokio::test]
    async fn intact_chain_verifies() {
        let db = Db::fake();
        seed_chain(&db, 10).await;
        let outcome = verify(&db, 1).await.unwrap();
        assert!(outcome.ok, "{outcome:?}");
        assert_eq!(outcome.records_verified, 10);
    }

    #[tokio::test]
    async fn paged_chain_across_multiple_pages_verifies() {
        // PAGE_SIZE is 500; seed enough to force at least 2 pages.
        let db = Db::fake();
        seed_chain(&db, 550).await;
        let outcome = verify(&db, 1).await.unwrap();
        assert!(outcome.ok, "{outcome:?}");
        assert_eq!(outcome.records_verified, 550);
    }
}
