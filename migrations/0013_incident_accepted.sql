-- "Known, leave it": a person accepts a standing fault (IncidentRepo::accept).
-- The incident stays open and acknowledged, so re-detections attach to it,
-- notifications stop, and scans are told not to re-investigate it.
-- Additive only.
ALTER TABLE incidents ADD COLUMN accepted_at TEXT;  -- RFC3339
ALTER TABLE incidents ADD COLUMN accepted_by TEXT;  -- account uuid
