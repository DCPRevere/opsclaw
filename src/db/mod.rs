//! Persistence: trait-per-repo (gianna pattern), SQLite impl + in-memory
//! fake, one parity suite over both with SQLite as the spec.
//!
//! Wave 1 builds the implementations, the migrations, and the parity suite,
//! and adds the remaining repos whose domain types are gianna ports
//! (`JobRepo` with `Schedule`/`Job`, `RunbookRunRepo`). Targets/resources are
//! NOT here — config declares them (brief invariant #4); the DB holds runtime
//! state only.

pub mod memory;
pub mod repo;
pub mod sqlite;

pub use repo::{
    Account, AccountRepo, ApprovalRepo, AuditRepo, ChannelStateRepo, ChatMessage, ChatRepo,
    CliToken, ControlRepo, IncidentRepo, Invite, InviteRepo, JobFailure, JobRepo, PushSubscription,
    PushSubscriptionRepo, RunbookRun, RunbookRunRepo, RunbookSuccessRate, StepOutcome, StepStatus,
    TelegramBinding, TokenRepo,
};

use std::sync::Arc;

/// The union of every repo trait, so integration code (the scheduler,
/// http/state.rs in a later wave) can hold ONE `Arc<dyn AllRepos>` and reach
/// every table — mirrors gianna's `AllRepos`/`AppState::with_repos` pattern
/// (`src/http/state.rs`). Both [`sqlite::SqliteDb`] and [`memory::InMemoryDb`]
/// implement every repo trait, so the blanket impl below covers them.
pub trait AllRepos:
    IncidentRepo
    + ApprovalRepo
    + AuditRepo
    + AccountRepo
    + ControlRepo
    + JobRepo
    + RunbookRunRepo
    + TokenRepo
    + InviteRepo
    + PushSubscriptionRepo
    + ChannelStateRepo
    + ChatRepo
{
}

impl<T> AllRepos for T where
    T: IncidentRepo
        + ApprovalRepo
        + AuditRepo
        + AccountRepo
        + ControlRepo
        + JobRepo
        + RunbookRunRepo
        + TokenRepo
        + InviteRepo
        + PushSubscriptionRepo
        + ChannelStateRepo
        + ChatRepo
{
}

/// The daemon's one backing store, as a single `Arc<dyn AllRepos>` — the
/// bundle integration code holds (gianna's `AppState` repo-field pattern,
/// collapsed to one handle since every repo here shares one struct per
/// backend). `Db::connect` is the live path (SQLite, boot-time migrate);
/// `Db::fake` is the in-memory fakes-mode / test path.
#[derive(Clone)]
pub struct Db(Arc<dyn AllRepos>);

impl Db {
    /// Connect to (creating if absent) and migrate a SQLite database at
    /// `path` — a plain filesystem path or a `sqlite:` URL understood by
    /// sqlx (see [`sqlite::SqliteDb::connect`]).
    pub async fn connect(path: &str) -> crate::Result<Self> {
        Ok(Db(Arc::new(sqlite::SqliteDb::connect(path).await?)))
    }

    /// The in-memory fake store (fakes mode / tests). Every call returns an
    /// independent store.
    pub fn fake() -> Self {
        Db(Arc::new(memory::InMemoryDb::new()))
    }

    /// The shared handle, for wiring into whatever holds one `Arc` per repo
    /// trait (each `Arc<dyn XRepo>` clone is cheap — same underlying store).
    pub fn repos(&self) -> Arc<dyn AllRepos> {
        self.0.clone()
    }
}
