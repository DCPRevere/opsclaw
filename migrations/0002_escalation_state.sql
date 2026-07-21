-- Durable escalation-chain position (incidents::escalation::EscalationState):
-- which step of the contact chain is being notified and when that step's
-- ack_timeout clock started. Without these, a daemon restart mid-escalation
-- would re-start the chain from priority 0.
ALTER TABLE incidents ADD COLUMN escalation_step INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN step_started_at TEXT;  -- RFC3339
