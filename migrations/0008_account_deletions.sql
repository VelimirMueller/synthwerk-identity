-- 0008_account_deletions: accounts their users deleted (synthwerk#41).
-- Number 0008, not 0007: open PRs for #37 and #38 already use 0007. Files run in
-- name order; gaps are fine. No other migration depends on this table.
-- One row per deleted user, keyed by sha256 of the sub. The row stays after the
-- delete: the Zitadel hook drops late grant events of the user with it, and a repeat
-- request finds it. user_sub holds the clear sub only until Zitadel removed the user
-- (the remover needs it); then it is set to NULL.
CREATE TABLE IF NOT EXISTS identity.account_deletions (
    user_sub_hash       bytea       PRIMARY KEY CHECK (octet_length(user_sub_hash) = 32),
    user_sub            text        CHECK (user_sub ~ '^[A-Za-z0-9_-]{1,128}$'),
    requested_at        timestamptz NOT NULL DEFAULT now(),
    zitadel_removed_at  timestamptz,
    attempts            integer     NOT NULL DEFAULT 0,
    next_attempt_at     timestamptz NOT NULL DEFAULT now(),
    last_error          text,
    -- The clear sub goes once Zitadel removed the user.
    CHECK ((zitadel_removed_at IS NULL) = (user_sub IS NOT NULL))
);

-- The remover reads the open rows, the next one first.
CREATE INDEX IF NOT EXISTS account_deletions_open
    ON identity.account_deletions (next_attempt_at) WHERE zitadel_removed_at IS NULL;
