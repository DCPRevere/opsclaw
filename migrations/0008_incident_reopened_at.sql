-- Re-detection timestamp for incidents re-opened out of Expired: an
-- escalation chain that exhausted unacked leaves the fault standing, and the
-- next scan re-detects it. Re-opening the SAME row (IncidentRepo::reopen)
-- instead of inserting a duplicate is what stops a long-standing fault from
-- churning a fresh notification cycle per scan. opened_at keeps the ORIGINAL
-- detection (age-tracking); NULL on rows never re-opened.
ALTER TABLE incidents ADD COLUMN reopened_at TEXT;  -- RFC3339
