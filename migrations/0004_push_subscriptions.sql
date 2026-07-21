-- Additive: web-push subscriptions (DESIGN.md §3 channels / §4 HTTP gateway:
-- "Web push (gianna's push.rs ported) is a send-only channel... incident
-- alerts and approval requests deep-linking into the installed PWA"). One row
-- per subscribed device/browser; unlike gianna's household-scoped table this
-- is keyed to the single-tenant operator account (DESIGN §1: no tenancy ids).

CREATE TABLE push_subscriptions (
    endpoint     TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL,           -- UUID, text-encoded; owning operator
    p256dh       TEXT NOT NULL,
    auth         TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_push_subscriptions_account ON push_subscriptions (account_id);
