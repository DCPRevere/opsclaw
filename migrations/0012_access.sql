-- Access control (crate::access, docs/plans/ACCESS.md).
--
-- Additive only: new tables, nothing existing changes.

-- The IdP groups (or app roles) an account held at its last sign-in.
-- Replaced wholesale at each sign-in, so a group removed at the IdP stops
-- counting at the next login.
CREATE TABLE account_groups (
    account_id  TEXT PRIMARY KEY REFERENCES accounts(id),
    groups      TEXT NOT NULL,          -- JSON array of strings
    updated_at  TEXT NOT NULL
);

-- Time-boxed raw access to one data class in one scope.
CREATE TABLE access_elevations (
    id            TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts(id),
    scope         TEXT NOT NULL,
    class         TEXT NOT NULL,
    reason        TEXT NOT NULL,
    requested_at  TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    state         TEXT NOT NULL,        -- pending | active | denied | revoked
    decided_by    TEXT
);

CREATE INDEX idx_access_elevations_account ON access_elevations (account_id);

-- What a finding (incident, chat message) was built from, and an optional
-- hand-set restriction to named people or groups.
CREATE TABLE finding_labels (
    kind           TEXT NOT NULL,       -- incident | chat
    id             TEXT NOT NULL,
    labels         TEXT NOT NULL,       -- JSON array of {target, class}
    restricted_to  TEXT,                -- JSON array of emails/groups, or NULL
    PRIMARY KEY (kind, id)
);
