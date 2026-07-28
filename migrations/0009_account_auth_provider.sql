-- Which identity provider an operator account authenticates through, and
-- the provider's own immutable subject id for that operator.
--
-- Additive and nullable-only. `password_hash` stays NOT NULL: SQLite cannot
-- relax a NOT NULL in place, so an account with no local password stores the
-- `auth::NO_PASSWORD` sentinel, which `verify_password` refuses.
--
-- Accounts bind to the provider's SUBJECT, never to email: email is mutable
-- at the identity provider, `accounts.email` has no COLLATE NOCASE, and a
-- passkey-only identity may carry no email at all.

ALTER TABLE accounts ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local';
ALTER TABLE accounts ADD COLUMN external_subject TEXT;

-- One operator per external identity. Partial, so the many `local` rows —
-- which all have a NULL subject — are not forced to collide.
CREATE UNIQUE INDEX idx_accounts_external_subject
    ON accounts (auth_provider, external_subject)
    WHERE external_subject IS NOT NULL;
