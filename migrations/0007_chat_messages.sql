-- The shared team chat transcript, durable (DESIGN §3's "one shared
-- conversation" previously lived only in ChatTurn's in-memory Vec — a
-- restart erased the team's chat history even though every other surface
-- survives). Rows are append-only; `seq` is the total order every reader
-- relies on (wall-clock `ts` can tie within a second).
--   role: 'user' | 'assistant' | 'tool'  ('tool' rows are the agent's tool
--         calls made mid-turn, rendered in the chat log for transparency —
--         they are NOT part of the LLM replay transcript, which stays
--         in-memory and user/assistant only)
--   speaker: operator display name for 'user'; 'assistant' for replies;
--            the tool name for 'tool' rows.
CREATE TABLE chat_messages (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    role    TEXT NOT NULL,
    speaker TEXT NOT NULL,
    content TEXT NOT NULL
);
