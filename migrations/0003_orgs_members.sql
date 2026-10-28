-- 0003_orgs_members: orgs and their members (synthwerk#29).
-- An org is a Zitadel org. identity mirrors the Zitadel user grants of the project
-- synthwerk-api as memberships. operator is a platform role and never a row here.
CREATE TABLE IF NOT EXISTS identity.orgs (
    id              uuid        PRIMARY KEY,
    zitadel_org_id  text        NOT NULL UNIQUE,
    name            text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    slug            text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z][a-z0-9-]{1,63}$'),
    -- pending: identity knows the org but no owner yet. active: it has an owner;
    -- org.created was written in the same transaction.
    status          text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active')),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity.memberships (
    org_id            uuid        NOT NULL REFERENCES identity.orgs (id) ON DELETE CASCADE,
    user_sub          text        NOT NULL CHECK (user_sub ~ '^[A-Za-z0-9_-]{1,128}$'),
    role              text        NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    -- The Zitadel user grant behind the row. Identity writes role changes to it.
    zitadel_grant_id  text        UNIQUE,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_sub)
);

-- Second guard after the row lock in the service: at commit, an active org still
-- has at least one owner.
CREATE OR REPLACE FUNCTION identity.memberships_keep_an_owner() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity.orgs o WHERE o.id = OLD.org_id AND o.status = 'active')
       AND NOT EXISTS (SELECT 1 FROM identity.memberships m WHERE m.org_id = OLD.org_id AND m.role = 'owner') THEN
        RAISE EXCEPTION 'org % has no owner', OLD.org_id USING ERRCODE = '23514', CONSTRAINT = 'memberships_keep_an_owner';
    END IF;
    RETURN NULL;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'memberships_keep_an_owner'
                   AND tgrelid = 'identity.memberships'::regclass) THEN
        CREATE CONSTRAINT TRIGGER memberships_keep_an_owner
            AFTER UPDATE OR DELETE ON identity.memberships
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION identity.memberships_keep_an_owner();
    END IF;
END;
$$;
