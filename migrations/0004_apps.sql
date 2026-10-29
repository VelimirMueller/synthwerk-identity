-- 0004_apps: apps of an org and their origin allow-list (synthwerk#30).
-- A widget gets a widget token only on an origin of this list. The service stores
-- the canonical form (scheme://host[:port], lower case, no default port) and
-- compares exactly; the check here is a second guard on the shape.
CREATE TABLE IF NOT EXISTS identity.apps (
    id               uuid        PRIMARY KEY,
    org_id           uuid        NOT NULL REFERENCES identity.orgs (id) ON DELETE CASCADE,
    name             text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    allowed_origins  text[]      NOT NULL CHECK (
        cardinality(allowed_origins) BETWEEN 1 AND 20
        AND array_position(allowed_origins, NULL) IS NULL
    ),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- listApps pages by id (UUIDv7, so oldest first) inside one org.
CREATE INDEX IF NOT EXISTS apps_org_id ON identity.apps (org_id, id);
