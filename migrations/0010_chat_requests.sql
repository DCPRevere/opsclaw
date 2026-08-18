-- Durable chat idempotency. A client retry must never start a second agent
-- turn after the first may already have executed a tool. Pending and failed
-- rows therefore remain terminal for automatic replay; completed rows return
-- the original reply.
CREATE TABLE chat_requests (
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'failed')),
    reply           TEXT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    PRIMARY KEY (account_id, idempotency_key),
    CHECK (state != 'complete' OR reply IS NOT NULL)
);

CREATE INDEX idx_chat_requests_started_at ON chat_requests (started_at);
