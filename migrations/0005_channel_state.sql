-- Additive: persistent Telegram chat roster + generic channel key/value state
-- (DESIGN.md §3 channels: "Telegram is long-polling; persist the poll offset
-- only after genuine hand-off"). Replaces the in-memory-only
-- InMemoryRoster/InMemoryOffsetStore boot.rs wired with a documented KNOWN
-- LIMITATION (a restart forgot chat bindings and the poll cursor).
--
-- Two tables, deliberately separate:
--   * telegram_roster — one row per allowlisted chat id <-> operator binding;
--     shaped for the actual query patterns (`find_operator` by chat_id,
--     `chat_ids_for` by operator), not a generic blob.
--   * channel_state — a plain key/value table for small durable scalars a
--     channel needs across restarts (today: just the Telegram getUpdates
--     offset, under key "telegram:getUpdates:offset" — the exact constant
--     `channels::telegram::TELEGRAM_OFFSET_KEY` already uses). One row per
--     key, not "a single row" — kept general on purpose so a future second
--     channel with its own durable cursor doesn't need a new migration.

CREATE TABLE telegram_roster (
    chat_id      TEXT PRIMARY KEY,
    operator_id  TEXT NOT NULL,           -- UUID, text-encoded
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_telegram_roster_operator ON telegram_roster (operator_id);

CREATE TABLE channel_state (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
