//! Crate-wide error type (gianna's shape: one small enum, no error-crate zoo).

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(String),

    #[error("policy: {0}")]
    Policy(String),

    #[error("not found: {0}")]
    NotFound(String),

    /// Optimistic-concurrency loser (e.g. a versioned row update raced another
    /// writer). Callers generally log at debug and re-read, not surface.
    #[error("conflict: {0}")]
    Conflict(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A database-layer failure (sqlx). Kept as its own variant (rather than
    /// folded into `Other`) so callers can match on it distinctly from a
    /// generic internal error if they ever need to.
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
