-- Split the original team-wide transcript into one global Operations room
-- and one room per configured project environment. Existing history remains
-- available in Operations. turn_id correlates live SSE rows with the request
-- that produced them, so concurrent rooms cannot clear each other's UI state.
ALTER TABLE chat_messages ADD COLUMN conversation TEXT NOT NULL DEFAULT 'operations';
ALTER TABLE chat_messages ADD COLUMN turn_id TEXT;

CREATE INDEX idx_chat_messages_conversation_seq
    ON chat_messages (conversation, seq DESC);

-- Idempotency keys remain account-wide. Recording the room lets a replay with
-- the same key in a different room fail closed instead of returning unrelated
-- content.
ALTER TABLE chat_requests ADD COLUMN conversation TEXT NOT NULL DEFAULT 'operations';
