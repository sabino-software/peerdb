-- Additive foundation for dual-reading legacy DBType peers and exact plugin
-- references. NULL plugin fields mean the peer/flow still uses the in-process
-- compatibility path; no existing row changes execution behavior in this
-- migration.
ALTER TABLE peers ADD COLUMN IF NOT EXISTS connector_id TEXT;
ALTER TABLE peers ADD COLUMN IF NOT EXISTS plugin_id TEXT;
ALTER TABLE peers ADD COLUMN IF NOT EXISTS plugin_version TEXT;
ALTER TABLE peers ADD COLUMN IF NOT EXISTS plugin_digest TEXT;
ALTER TABLE peers ADD COLUMN IF NOT EXISTS config_schema_version INTEGER;
ALTER TABLE peers ADD COLUMN IF NOT EXISTS config_encoding TEXT;

UPDATE peers
SET connector_id = CASE type
    WHEN 0 THEN 'bigquery'
    WHEN 1 THEN 'snowflake'
    WHEN 2 THEN 'mongodb'
    WHEN 3 THEN 'postgresql'
    WHEN 5 THEN 's3'
    WHEN 6 THEN 'sqlserver'
    WHEN 7 THEN 'mysql'
    WHEN 8 THEN 'clickhouse'
    WHEN 9 THEN 'kafka'
    WHEN 10 THEN 'pubsub'
    WHEN 11 THEN 'eventhubs'
    WHEN 12 THEN 'elasticsearch'
    WHEN 13 THEN 'cockroachdb'
    ELSE NULL
END
WHERE connector_id IS NULL;

COMMENT ON COLUMN peers.connector_id IS
    'Stable connector descriptor ID; backfilled for legacy peers without enabling plugin execution';
COMMENT ON COLUMN peers.plugin_id IS
    'Exact plugin artifact ID; NULL selects the legacy in-process compatibility path';
COMMENT ON COLUMN peers.plugin_version IS
    'Exact plugin semantic version; never a floating constraint';
COMMENT ON COLUMN peers.plugin_digest IS
    'Exact content digest such as sha256:<hex> for the selected platform bundle';
COMMENT ON COLUMN peers.config_schema_version IS
    'Connector-owned configuration schema version for the encrypted options payload';
COMMENT ON COLUMN peers.config_encoding IS
    'Encoding of the encrypted options payload, initially canonical-json';

ALTER TABLE flows ADD COLUMN IF NOT EXISTS source_plugin_id TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS source_connector_id TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS source_plugin_version TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS source_plugin_digest TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS source_protocol_minor INTEGER;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS source_config_schema_version INTEGER;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS destination_plugin_id TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS destination_connector_id TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS destination_plugin_version TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS destination_plugin_digest TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS destination_protocol_minor INTEGER;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS destination_config_schema_version INTEGER;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS plugin_record_format TEXT;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS plugin_capability_plan JSONB;

COMMENT ON COLUMN flows.source_connector_id IS
    'Exact source descriptor within the pinned plugin artifact';
COMMENT ON COLUMN flows.destination_connector_id IS
    'Exact destination descriptor within the pinned plugin artifact';
COMMENT ON COLUMN flows.plugin_record_format IS
    'Exact negotiated transport format; NULL means the legacy in-process flow path';
COMMENT ON COLUMN flows.plugin_capability_plan IS
    'Versioned source/destination capability revisions pinned when the flow is planned';
