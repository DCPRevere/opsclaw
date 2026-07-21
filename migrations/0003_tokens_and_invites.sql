-- Additive (Wave 4, src/http/): remote-CLI personal access tokens and
-- teammate invites. Neither existed in the Wave 0 frozen contract or
-- migration 0001; added per AGENTS.md's additive-only rule, following
-- gianna's CliTokenRepo/invite pattern (hash-only token storage; a
-- code-based invite, atomically consumed on join).

CREATE TABLE cli_tokens (
    id             TEXT PRIMARY KEY,        -- UUID, text-encoded
    account_id     TEXT NOT NULL,
    name           TEXT NOT NULL,           -- device/host label
    token_hash     TEXT NOT NULL UNIQUE,    -- sha256 hex; plaintext never stored
    created_at     TEXT NOT NULL,
    last_used_at   TEXT
);

CREATE INDEX idx_cli_tokens_account ON cli_tokens (account_id);

CREATE TABLE invites (
    code         TEXT PRIMARY KEY,
    issued_by    TEXT NOT NULL,             -- account id
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT                       -- NULL until taken; kept (not deleted) for audit
);

CREATE INDEX idx_invites_open ON invites (expires_at) WHERE consumed_at IS NULL;
