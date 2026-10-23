-- 0002_zitadel_event_seen: Zitadel Action calls that identity has handled (#28).
-- The key is <instance>:<aggregate type>:<aggregate id>:<sequence>. A repeat of a
-- call finds its key and writes no second outbox row.
CREATE TABLE IF NOT EXISTS identity.zitadel_event_seen (
    event_key    text        PRIMARY KEY,
    received_at  timestamptz NOT NULL DEFAULT now()
);
