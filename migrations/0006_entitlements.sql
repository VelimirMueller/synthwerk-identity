-- 0006_entitlements: the plan of an org and its limits (synthwerk#31).
-- Number 0006, not 0004: open PRs #14 (0004_apps) and #15 (0004_mfa_evidence)
-- already use 0004. Files run in name order; gaps are fine.
-- One row per active org. The row holds the resolved limits, so an event always
-- tells the state the org really has. 0 means no limit. A day is a UTC day.
CREATE TABLE IF NOT EXISTS identity.org_entitlements (
    org_id                       uuid        PRIMARY KEY REFERENCES identity.orgs (id) ON DELETE CASCADE,
    plan                         text        NOT NULL CHECK (plan ~ '^[a-z][a-z0-9_]{0,31}$'),
    llm_tokens_per_user_per_day  bigint      NOT NULL CHECK (llm_tokens_per_user_per_day >= 0),
    llm_tokens_per_org_per_day   bigint      NOT NULL CHECK (llm_tokens_per_org_per_day >= 0),
    apps_per_org                 integer     NOT NULL CHECK (apps_per_org BETWEEN 0 AND 10000),
    -- Goes up by one on every change; the event carries the same value.
    version                      bigint      NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_at                   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS org_entitlements_plan ON identity.org_entitlements (plan);
