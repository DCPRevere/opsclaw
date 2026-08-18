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

/// One blocked-action entry: a mutation the agent WOULD have run, refused by
/// the autonomy gate (observe mode) and recorded in the audit chain
/// (`policy::mod`: the audit record is the blocked-action log).
#[derive(Debug, Serialize)]
pub struct DryRunEntry {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub principal: String,
    pub target: String,
    pub tool: String,
    pub command: String,
    pub risk: String,
}

/// `opsclaw-cli blocked-actions` — the most recent `limit` autonomy-blocked
/// commands, oldest first (so reading top-to-bottom follows time). This is
/// the promotion-review surface: before raising a target from `observe` to
/// `suggest`, read what it WOULD have done. Walks the chain forward keeping
/// a bounded tail — the chain is append-only and unbounded, the answer
/// isn't.
pub async fn blocked_actions(db: &Db, limit: usize) -> Result<Vec<DryRunEntry>> {
    let mut cursor = 1i64;
    let mut tail: std::collections::VecDeque<DryRunEntry> = Default::default();
    loop {
        let page = db.repos().range(cursor, PAGE_SIZE).await?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len() as i64;
        cursor = page.last().map(|r| r.seq + 1).unwrap_or(cursor);
        for r in page {
            if matches!(r.outcome, crate::audit::AuditOutcome::Blocked) {
                if tail.len() == limit {
                    tail.pop_front();
                }
                tail.push_back(DryRunEntry {
                    ts: r.ts,
                    principal: r.principal.to_string(),
                    target: r.fq_target,
                    tool: r.tool,
                    command: r.command,
                    risk: r.risk.to_string(),
                });
            }
        }
        if page_len < PAGE_SIZE {
            break;
        }
    }
    Ok(tail.into())
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
    async fn blocked_actions_returns_only_blocked_records_bounded_by_limit() {
        let db = Db::fake();
        let mut tail: Option<AuditRecord> = None;
        for seq in 1..=8 {
            let mut r = unsealed_record(seq);
            // Odd seqs are autonomy-blocked mutations; even ran fine.
            if seq % 2 == 1 {
                r.outcome = AuditOutcome::Blocked;
                r.command = format!("kubectl delete pod x-{seq}");
                r.risk = RiskClass::Destructive;
            }
            let sealed = chain::seal(r, tail.as_ref()).unwrap();
            db.repos().append(&sealed).await.unwrap();
            tail = Some(sealed);
        }

        let all = blocked_actions(&db, 10).await.unwrap();
        assert_eq!(all.len(), 4);
        assert!(all.iter().all(|e| e.command.starts_with("kubectl delete")));

        // Bounded: only the MOST RECENT `limit` entries survive, in time order.
        let last_two = blocked_actions(&db, 2).await.unwrap();
        assert_eq!(last_two.len(), 2);
        assert_eq!(last_two[0].command, "kubectl delete pod x-5");
        assert_eq!(last_two[1].command, "kubectl delete pod x-7");
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

/// One chain record, flattened for display.
///
/// The chain has always been verifiable and never readable: `AuditRepo::
/// range`'s own doc says it exists for "`audit verify` and inspection", but
/// only verify was ever built. So an operator could prove the log was
/// untampered and had no way to see what was in it — which makes the
/// append-only, hash-chained record of every action the agent took
/// unavailable for exactly the question it exists to answer: what did it do?
///
/// `command` is the post-scrubbing command line (`AuditRecord::command`),
/// so secret VALUES were never written here in the first place.
#[derive(Debug, Serialize)]
pub struct AuditView {
    pub seq: i64,
    pub ts: String,
    pub principal: String,
    pub target: String,
    pub tool: String,
    pub command: String,
    pub risk: String,
    pub outcome: String,
    pub exit_code: Option<i32>,
    pub hash: String,
    pub prev_hash: String,
}

impl From<&crate::audit::AuditRecord> for AuditView {
    fn from(r: &crate::audit::AuditRecord) -> Self {
        AuditView {
            seq: r.seq,
            ts: r.ts.to_rfc3339(),
            principal: format!("{:?}", r.principal),
            target: r.fq_target.clone(),
            tool: r.tool.clone(),
            command: r.command.clone(),
            risk: format!("{:?}", r.risk).to_lowercase(),
            outcome: format!("{:?}", r.outcome).to_lowercase(),
            exit_code: r.exit_code,
            hash: r.hash.clone(),
            prev_hash: r.prev_hash.clone(),
        }
    }
}

/// Read a window of the chain, oldest first.
///
/// Paged through `AuditRepo::range` like [`verify`] rather than loading the
/// table: an audit chain is append-only and grows without bound.
pub async fn list(db: &Db, from_seq: i64, limit: i64) -> Result<Vec<AuditView>> {
    use crate::db::AuditRepo;
    let repos = db.repos();
    let rows = AuditRepo::range(&*repos, from_seq.max(1), limit).await?;
    Ok(rows.iter().map(AuditView::from).collect())
}

/// One record by its sequence number.
pub async fn show(db: &Db, seq: i64) -> Result<AuditView> {
    use crate::db::AuditRepo;
    let repos = db.repos();
    let rows = AuditRepo::range(&*repos, seq, 1).await?;
    rows.first()
        .filter(|r| r.seq == seq)
        .map(AuditView::from)
        .ok_or_else(|| crate::Error::Config(format!("no audit record at seq {seq}")))
}

/// The tail of the chain — what `audit list` shows with no arguments.
///
/// Defaults to the END rather than the beginning: an operator reaching for
/// the audit log is nearly always asking "what just happened?", and starting
/// at genesis on a long-lived deployment answers a question nobody asked.
pub async fn tail(db: &Db, limit: i64) -> Result<Vec<AuditView>> {
    use crate::db::AuditRepo;
    let repos = db.repos();
    let last = AuditRepo::last(&*repos).await?;
    let Some(last) = last else { return Ok(Vec::new()) };
    let from = (last.seq - limit + 1).max(1);
    list(db, from, limit).await
}

/// Render chain records for a human, one block each.
pub fn render(views: &[AuditView]) -> String {
    if views.is_empty() {
        return "the audit chain is empty — the agent has taken no recorded action yet.\n"
            .to_string();
    }
    let mut out = String::new();
    for r in views {
        out.push_str(&format!("#{}  {}  [{}] {}\n", r.seq, r.ts, r.risk, r.outcome));
        out.push_str(&format!("  target      {}\n", r.target));
        out.push_str(&format!("  tool        {}\n", r.tool));
        out.push_str(&format!("  command     {}\n", r.command));
        out.push_str(&format!("  by          {}\n", r.principal));
        if let Some(code) = r.exit_code {
            out.push_str(&format!("  exit        {code}\n"));
        }
        out.push('\n');
    }
    out.push_str("`opsclaw-cli audit verify` proves this chain has not been altered.\n");
    out
}
