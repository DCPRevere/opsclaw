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

    /// Additive (Wave 4, `http/`): request auth failed or was never presented
    /// — no session cookie, a bad/expired JWT, a revoked `token_version`, an
    /// unrecognised CLI/webhook token. Gianna's variant, ported verbatim
    /// (`src/error.rs`): `http::IntoResponse` maps this to 401.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Additive (Wave 4, `http/`): a request was well-formed but its content
    /// failed a business-rule check (bad shape, out-of-range value). Distinct
    /// from `Config` (a boot-time misconfiguration) — this is a per-request
    /// 400, never fatal to the daemon. Gianna's `Error::validation`, ported.
    #[error("validation: {0}")]
    Validation(String),

    /// Additive (Wave 4, `http/`): too many requests from one caller within a
    /// window (login/auth-exchange abuse). Carries the window so the response
    /// can set `Retry-After`. Gianna's `Error::RateLimited`, ported.
    #[error("rate limited: {message}")]
    RateLimited { message: String, retry_after_secs: u64 },

    /// Additive (web chat): a request hit a seam that is intentionally
    /// unwired on this state — `channels::NoopChat` in fakes mode, chiefly.
    /// Distinct from `Config` (a genuine boot-time misconfiguration that
    /// SHOULD be a loud 500): this is the expected shape of "you're running
    /// without the real agent loop wired up", so `http::IntoResponse` maps
    /// it to 503 with the message shown verbatim, never masked like a 500.
    #[error("unavailable: {0}")]
    Unavailable(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A model call failed. `dcpr_llm::Error` already classifies the
    /// failure as transient, hard or a context overflow, which the fallback
    /// chain and the agent loop act on.
    #[error(transparent)]
    Llm(#[from] dcpr_llm::Error),

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

    /// Additive (Wave 4): a request auth failure.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Error::Unauthorized(msg.into())
    }

    /// Additive (Wave 4): a request failed a business-rule validation.
    pub fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }

    /// Additive (Wave 4): too many requests; `retry_after_secs` becomes the
    /// response's `Retry-After` header.
    pub fn rate_limited(msg: impl Into<String>, retry_after_secs: u64) -> Self {
        Error::RateLimited { message: msg.into(), retry_after_secs }
    }

    /// Additive (web chat): a seam that is intentionally unwired on this
    /// state (see [`Error::Unavailable`]'s own doc).
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Error::Unavailable(msg.into())
    }

    /// A transient LLM failure worth retrying / falling through.
    pub fn llm_transient(msg: impl Into<String>) -> Self {
        Error::Llm(dcpr_llm::Error::transient(msg))
    }

    /// A hard LLM failure (don't retry the same provider).
    pub fn llm_hard(msg: impl Into<String>) -> Self {
        Error::Llm(dcpr_llm::Error::hard(msg))
    }

    /// Whether this is an LLM failure worth retrying or falling through.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Llm(e) if e.is_retryable())
    }

    /// True when this is a context-window overflow.
    pub fn is_context_overflow(&self) -> bool {
        matches!(self, Error::Llm(e) if e.is_context_overflow())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
