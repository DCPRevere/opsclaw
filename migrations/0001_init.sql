-- OpsClaw persistence: SQLite (single-tenant daemon, DESIGN.md §7.2). Every
-- domain type that isn't pure config (incidents, approvals, audit, jobs,
-- claims, runbook runs) lives here. WAL mode + busy_timeout are set at
-- connect time (src/db/sqlite/mod.rs), not in this file.
--
-- Applied migrations are immutable (AGENTS.md) — a schema change is always a
-- NEW numbered file, never an edit to this one.

-- ---- Incidents ----

CREATE TABLE incidents (
    id                  TEXT PRIMARY KEY,      -- UUID, text-encoded
    fingerprint         TEXT NOT NULL,         -- anti-spam dedup identity
    target              TEXT NOT NULL,         -- FqTarget, JSON-encoded
    severity            TEXT NOT NULL,
    state               TEXT NOT NULL,
    signals             TEXT NOT NULL,
    hypothesis          TEXT NOT NULL,
    recommended_action  TEXT,
    opened_at           TEXT NOT NULL,         -- RFC3339
    acked_at            TEXT,
    acked_by            TEXT,                  -- UUID
    resolved_at         TEXT,
    last_notified_at    TEXT,
    notify_count        INTEGER NOT NULL DEFAULT 0
);

-- The anti-spam lookup: one open (Active/Acknowledged) incident per
-- fingerprint. Enforced at the query layer (state is a TEXT column, not a
-- CHECK-able enum), but indexed here for the hot lookup path.
CREATE INDEX idx_incidents_fingerprint_open ON incidents (fingerprint, state);
CREATE INDEX idx_incidents_opened_at ON incidents (opened_at DESC);

-- ---- Approvals ----

CREATE TABLE approvals (
    id             TEXT PRIMARY KEY,
    incident       TEXT,                        -- UUID, nullable
    requested_by   TEXT NOT NULL,                -- Principal, JSON-encoded
    target         TEXT NOT NULL,                -- FqTarget, JSON-encoded
    tool           TEXT NOT NULL,
    command        TEXT NOT NULL,
    risk           TEXT NOT NULL,
    hypothesis     TEXT NOT NULL,
    state          TEXT NOT NULL,
    requested_at   TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    decided_at     TEXT,
    decided_by     TEXT                          -- UUID, nullable
);

CREATE INDEX idx_approvals_state ON approvals (state);
CREATE INDEX idx_approvals_expires_at ON approvals (expires_at) WHERE state = 'pending';

-- ---- Audit (hash-chained, append-only) ----

CREATE TABLE audit_log (
    id           TEXT PRIMARY KEY,
    seq          INTEGER NOT NULL UNIQUE,        -- monotonic chain position
    ts           TEXT NOT NULL,
    principal    TEXT NOT NULL,                  -- Principal, JSON-encoded
    fq_target    TEXT NOT NULL,
    tool         TEXT NOT NULL,
    command      TEXT NOT NULL,
    risk         TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    exit_code    INTEGER,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL
);

CREATE INDEX idx_audit_seq ON audit_log (seq);

-- ---- Accounts (operator web UI auth) ----

CREATE TABLE accounts (
    id             TEXT PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    display_name   TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    token_version  INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);

-- ---- Jobs (scheduled recurring jobs) ----

CREATE TABLE jobs (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    schedule     TEXT NOT NULL,                  -- Schedule, JSON-encoded
    payload      TEXT NOT NULL,                  -- Payload, JSON-encoded
    enabled      INTEGER NOT NULL DEFAULT 1,      -- boolean
    system       INTEGER NOT NULL DEFAULT 0,      -- boolean
    next_run_at  TEXT,
    last_run_at  TEXT,
    created_at   TEXT NOT NULL,
    version      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_jobs_due ON jobs (next_run_at) WHERE enabled = 1;

-- Job occurrence failure/retry-budget tracking.
CREATE TABLE job_failures (
    job_id           TEXT NOT NULL,
    occurrence_key   TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 1,
    first_failed_at  TEXT NOT NULL,
    last_failed_at   TEXT NOT NULL,
    last_error       TEXT NOT NULL,
    PRIMARY KEY (job_id, occurrence_key)
);

-- ---- Claims (crash-safe exactly-once, generalized digest_sends) ----

CREATE TABLE claims (
    kind        TEXT NOT NULL,
    key         TEXT NOT NULL,
    claimed_at  TEXT NOT NULL,
    UNIQUE (kind, key)
);

CREATE INDEX idx_claims_claimed_at ON claims (claimed_at);

-- ---- Control (e-stop) ----

CREATE TABLE control_state (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- ---- Runbook runs ----

CREATE TABLE runbook_runs (
    id            TEXT PRIMARY KEY,
    runbook_name  TEXT NOT NULL,
    fq_target     TEXT NOT NULL,
    principal     TEXT NOT NULL,                 -- Principal, JSON-encoded
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    success       INTEGER NOT NULL,               -- boolean
    steps         TEXT NOT NULL                   -- Vec<RunbookStepResult>, JSON-encoded
);

CREATE INDEX idx_runbook_runs_name ON runbook_runs (runbook_name, started_at DESC);
