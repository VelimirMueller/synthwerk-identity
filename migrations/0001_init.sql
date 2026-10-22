-- 0001_init: the identity schema and the outbox table (D-07).
-- The service applies this file at startup, the same way pulse applies its schema.
CREATE SCHEMA IF NOT EXISTS identity;

-- The outbox table of the kit package outbox, in the identity schema. The relay
-- publishes the rows to NATS JetStream with Nats-Msg-Id = the CloudEvents id.
CREATE TABLE IF NOT EXISTS identity.synthwerk_outbox (
    id            uuid        PRIMARY KEY,
    nats_subject  text        NOT NULL,
    event         jsonb       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    published_at  timestamptz,
    attempts      integer     NOT NULL DEFAULT 0,
    last_error    text
);
CREATE INDEX IF NOT EXISTS synthwerk_outbox_unpublished
    ON identity.synthwerk_outbox (created_at, id) WHERE published_at IS NULL;
