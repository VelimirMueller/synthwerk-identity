-- 0009_member_status_audit: member status and the audit list (synthwerk#37).
-- Every statement is idempotent: the service runs all migrations at every start.

-- invited: a new user has its grant but has not signed in to the org yet.
-- A deactivated member keeps the row and the role. Its Zitadel user grant is
-- deactivated, so tokens carry no org role, and every stored-role check fails.
ALTER TABLE identity.memberships
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'memberships_status_check'
                   AND conrelid = 'identity.memberships'::regclass) THEN
        ALTER TABLE identity.memberships
            ADD CONSTRAINT memberships_status_check CHECK (status IN ('active', 'deactivated', 'invited'));
    END IF;
END;
$$;

-- Pending invitations. The email is the one the admin typed; only owners and
-- admins of the org read it. user_sub is set when identity created the Zitadel
-- user; a user of another org has none and the invitation stays pending.
CREATE TABLE IF NOT EXISTS identity.invitations (
    id          uuid        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES identity.orgs (id) ON DELETE CASCADE,
    email       text        NOT NULL CHECK (char_length(email) BETWEEN 3 AND 254),
    role        text        NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    invited_by  text        NOT NULL,
    user_sub    text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    accepted_at timestamptz,
    -- An owner or admin revoked it. A revoked invitation is never accepted.
    revoked_at  timestamptz
);
CREATE INDEX IF NOT EXISTS invitations_pending ON identity.invitations (org_id, id DESC)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
-- One pending invitation per email and org: a repeat invite returns it.
CREATE UNIQUE INDEX IF NOT EXISTS invitations_pending_email ON identity.invitations (org_id, lower(email))
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- The last-owner guard counts active owners only (replaces the function of 0003).
-- Its trigger (0003) is a deferred AFTER UPDATE OR DELETE constraint trigger, so
-- it also covers a status change.
CREATE OR REPLACE FUNCTION identity.memberships_keep_an_owner() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity.orgs o WHERE o.id = OLD.org_id AND o.status = 'active')
       AND NOT EXISTS (SELECT 1 FROM identity.memberships m
                       WHERE m.org_id = OLD.org_id AND m.role = 'owner' AND m.status = 'active') THEN
        RAISE EXCEPTION 'org % has no owner', OLD.org_id USING ERRCODE = '23514', CONSTRAINT = 'memberships_keep_an_owner';
    END IF;
    RETURN NULL;
END;
$$;

-- The audit list: a copy of every org event identity writes to the outbox. The
-- outbox deletes published rows after 7 days; this table keeps them. seq orders
-- the list and is the page cursor.
CREATE TABLE IF NOT EXISTS identity.audit_events (
    seq         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id          uuid        NOT NULL UNIQUE,
    org_id      uuid        NOT NULL,
    type        text        NOT NULL,
    actor       text        NOT NULL,
    subject     text,
    time        timestamptz NOT NULL,
    data        jsonb       NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_events_org_seq ON identity.audit_events (org_id, seq DESC);

-- Copies an outbox row into audit_events when it is an identity event of a known
-- org. It runs in the transaction of the change: no change without its audit row.
CREATE OR REPLACE FUNCTION identity.outbox_to_audit() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    org text := NEW.event->>'orgid';
BEGIN
    IF org IS NULL
       OR org !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR NEW.event->>'type' NOT LIKE 'dev.synthwerk.identity.%'
       OR NOT EXISTS (SELECT 1 FROM identity.orgs o WHERE o.id = org::uuid) THEN
        RETURN NULL;
    END IF;
    BEGIN
        INSERT INTO identity.audit_events (id, org_id, type, actor, subject, time, data)
        VALUES (NEW.id, org::uuid, NEW.event->>'type', coalesce(NEW.event->>'actor', 'system'),
                NEW.event->>'subject', (NEW.event->>'time')::timestamptz, coalesce(NEW.event->'data', '{}'::jsonb))
        ON CONFLICT (id) DO NOTHING;
    EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR invalid_text_representation THEN
        -- A bad time never blocks the change itself. The kit validates events, so
        -- this does not happen for events of identity.
        RAISE WARNING 'audit: event % not copied: %', NEW.id, SQLERRM;
    END;
    RETURN NULL;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'outbox_to_audit'
                   AND tgrelid = 'identity.synthwerk_outbox'::regclass) THEN
        CREATE TRIGGER outbox_to_audit
            AFTER INSERT ON identity.synthwerk_outbox
            FOR EACH ROW EXECUTE FUNCTION identity.outbox_to_audit();
    END IF;
END;
$$;

-- Backfill: the outbox rows that still exist (published in the last 7 days).
-- Each row goes through the trigger function's rules; one bad row is skipped with
-- a warning and never blocks the start. ON CONFLICT makes a second start a no-op.
DO $$
DECLARE
    ob record;
BEGIN
    FOR ob IN SELECT id, event FROM identity.synthwerk_outbox
              WHERE event->>'type' LIKE 'dev.synthwerk.identity.%'
                AND event->>'orgid' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
              ORDER BY created_at, id LOOP
        BEGIN
            INSERT INTO identity.audit_events (id, org_id, type, actor, subject, time, data)
            SELECT ob.id, o.id, ob.event->>'type', coalesce(ob.event->>'actor', 'system'),
                   ob.event->>'subject', (ob.event->>'time')::timestamptz, coalesce(ob.event->'data', '{}'::jsonb)
            FROM identity.orgs o WHERE o.id = (ob.event->>'orgid')::uuid
            ON CONFLICT (id) DO NOTHING;
        EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR invalid_text_representation THEN
            RAISE WARNING 'audit backfill: event % skipped: %', ob.id, SQLERRM;
        END;
    END LOOP;
END;
$$;
