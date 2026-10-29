-- 0007_app_widget_settings: widget settings of an app (synthwerk#38).
-- The service checks every value (contracts WidgetSettings) and fills a missing
-- field with its default, so '{}' means "all defaults". The check here is a
-- second guard on the shape and the size.
ALTER TABLE identity.apps ADD COLUMN IF NOT EXISTS widget_settings jsonb NOT NULL DEFAULT '{}'::jsonb
    CONSTRAINT apps_widget_settings_shape CHECK (
        jsonb_typeof(widget_settings) = 'object'
        AND octet_length(widget_settings::text) <= 4096
    );
