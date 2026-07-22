-- The fault CLASS an incident was opened for ("disk-fill",
-- "cpu_saturation", ...) — always supplied to opsclaw_notify (it is a
-- required arg and a fingerprint component) but until now only present
-- INSIDE the fingerprint hash, so nothing could assert or display "what
-- kind of fault is this" without re-deriving it. Backfilled '' for
-- pre-existing rows: their class is unrecoverable from the hash.
ALTER TABLE incidents ADD COLUMN fault_class TEXT NOT NULL DEFAULT '';
