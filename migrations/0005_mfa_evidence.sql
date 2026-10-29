-- 0005_mfa_evidence: the newest sign-in per user that passed the MFA gate (#94).
-- The pre-access-token function copies amr from here into the access token.
-- It holds no session token.
CREATE TABLE IF NOT EXISTS identity.mfa_evidence (
    user_sub    text        PRIMARY KEY,
    session_id  text        NOT NULL,
    amr         text[]      NOT NULL,
    checked_at  timestamptz NOT NULL
);
