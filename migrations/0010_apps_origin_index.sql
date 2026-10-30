-- 0010_apps_origin_index: find the apps that list an origin (infra#21).
-- GET /internal/v1/widget-origins asks "does any app of an active org list this
-- origin?" with allowed_origins @> ARRAY[origin]. The GIN index answers it
-- without a scan of all apps. The table is small, so a plain CREATE INDEX is
-- fast at startup.
CREATE INDEX IF NOT EXISTS apps_allowed_origins ON identity.apps USING gin (allowed_origins);
