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

    /// An LLM provider call failed. `retryable` distinguishes transient
    /// (429/5xx/timeout) from hard (401/400/model-not-found) failures — the
    /// fallback chain (`llm::FallbackLlm`) retries the former on the same
    /// provider and falls through to the next provider on the latter.
    /// `retry_after_secs` carries a provider's `Retry-After` header when
    /// present, so backoff honours it instead of guessing.
    #[error("llm error ({}): {message}", if *.retryable { "transient" } else { "hard" })]
    Llm { message: String, retryable: bool, retry_after_secs: Option<u64> },

    /// The assembled prompt exceeded the model's context window. NEITHER
    /// transient (retrying the same oversized prompt always fails the same
    /// way) NOR ordinary-hard (a smaller prompt CAN succeed) — callers should
    /// shrink context and retry once; `FallbackLlm` fails fast on it (no
    /// retry, no fallthrough — every provider in the chain would 400 on the
    /// same prompt).
    #[error("llm context overflow: {0}")]
    LlmContextOverflow(String),

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
        Error::Llm { message: msg.into(), retryable: true, retry_after_secs: None }
    }

    /// A hard LLM failure (don't retry the same provider).
    pub fn llm_hard(msg: impl Into<String>) -> Self {
        Error::Llm { message: msg.into(), retryable: false, retry_after_secs: None }
    }

    /// A context-window overflow: the prompt was too big for the model.
    pub fn llm_context_overflow(msg: impl Into<String>) -> Self {
        Error::LlmContextOverflow(msg.into())
    }

    /// Whether this error is worth retrying or falling through to another
    /// provider.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Llm { retryable: true, .. })
    }

    /// True when this is a context-window overflow — `FallbackLlm` fails fast
    /// on it rather than retrying or falling through.
    pub fn is_context_overflow(&self) -> bool {
        matches!(self, Error::LlmContextOverflow(_))
    }

    /// The provider-supplied `Retry-After` (seconds) on a transient LLM
    /// failure, if any.
    pub fn llm_retry_after_secs(&self) -> Option<u64> {
        match self {
            Error::Llm { retry_after_secs, .. } => *retry_after_secs,
            _ => None,
        }
    }

    /// Classify an HTTP status into a retryable/hard LLM error, honouring a
    /// parsed `Retry-After` (seconds) when present.
    pub fn from_llm_status(
        status: u16,
        message: impl Into<String>,
        retry_after_secs: Option<u64>,
    ) -> Self {
        let message = message.into();
        // A context-window overflow arrives as a 400 (OpenAI-compat/
        // OpenRouter and Anthropic invalid_request naming the token/context
        // limit) or, rarely, a 413 payload-too-large. Restricted to 400/413
        // so a 429/408/5xx whose body happens to mention "context" stays
        // retryable (a transient blip must not be silently downgraded to a
        // non-retryable overflow).
        if (status == 400 || status == 413) && is_context_overflow_body(&message) {
            return Error::LlmContextOverflow(message);
        }
        let retryable = status == 429 || status == 408 || (500..=599).contains(&status);
        Error::Llm {
            message,
            retryable,
            // A Retry-After is only meaningful for a retryable status; drop it
            // on a hard failure so it can't stall a fallthrough.
            retry_after_secs: if retryable { retry_after_secs } else { None },
        }
    }
}

/// True when an LLM provider's error body names a context/token-limit
/// overflow, as opposed to any other 4xx (auth, bad model, malformed
/// request). Case-insensitive substring match on the provider's own message —
/// deliberately broad, because the caller's response (shrink + retry once) is
/// safe even on a false positive, whereas a MISS strands a turn with a
/// permanent generic failure.
fn is_context_overflow_body(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "context_length_exceeded",
        "context length exceeded",
        "maximum context length",
        "maximum context",
        "context window",
        "context_window_exceeded",
        "too many tokens",
        "too many input tokens",
        "reduce the length",
        "prompt is too long",
        "input is too long",
        "exceeds the maximum",
        "exceeds the context",
        "exceed context limit", // some OpenRouter upstreams
        "string too long",
    ];
    MARKERS.iter().any(|m| b.contains(m))
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
