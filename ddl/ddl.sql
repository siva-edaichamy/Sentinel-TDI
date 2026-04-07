-- =============================================================================
-- ddl.sql — Insider Threat Synthetic Data Pipeline
-- Greenplum 7.x | APPENDOPTIMIZED, zstd compression, distributed by employee_id
-- Schemas: insider_threat_bronze | insider_threat_silver | insider_threat_gold
-- =============================================================================

-- =============================================================================
-- SCHEMAS
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS insider_threat_bronze;
CREATE SCHEMA IF NOT EXISTS insider_threat_silver;
CREATE SCHEMA IF NOT EXISTS insider_threat_gold;

-- =============================================================================
-- BRONZE — Mapping tables and pipeline audit
-- =============================================================================

-- Pipeline run audit (all agents write here)
CREATE TABLE IF NOT EXISTS insider_threat_bronze.pipeline_runs (
    run_id              VARCHAR(64)     NOT NULL,
    agent_name          VARCHAR(50)     NOT NULL,
    started_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(20)     NOT NULL,   -- running | success | failure
    rows_in             INT,
    rows_out            INT,
    duration_seconds    FLOAT8,
    artifacts           TEXT[],
    notes               TEXT,
    PRIMARY KEY (run_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (run_id);

-- Badge → employee_id mapping
CREATE TABLE IF NOT EXISTS insider_threat_bronze.badge_registry (
    badge_id            VARCHAR(20)     NOT NULL,
    employee_id         VARCHAR(10)     NOT NULL,
    issued_date         DATE            NOT NULL,
    PRIMARY KEY (badge_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Machine → employee_id mapping (with effective dates for shared machines)
-- DISTRIBUTED BY (machine_id) — must be subset of PK (machine_id, effective_start)
CREATE TABLE IF NOT EXISTS insider_threat_bronze.asset_assignment (
    machine_id          VARCHAR(20)     NOT NULL,
    employee_id         VARCHAR(10)     NOT NULL,
    effective_start     DATE            NOT NULL,
    effective_end       DATE,           -- NULL = current assignment
    PRIMARY KEY (machine_id, effective_start)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (machine_id);

-- Email/Slack → employee_id mapping
-- DISTRIBUTED BY (email_address) — must match PK
CREATE TABLE IF NOT EXISTS insider_threat_bronze.directory (
    email_address       VARCHAR(255)    NOT NULL,
    slack_handle        VARCHAR(100)    NOT NULL,
    employee_id         VARCHAR(10)     NOT NULL,
    PRIMARY KEY (email_address)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (email_address);

-- Social handle → employee_id mapping (~5% unmapped for realism)
-- DISTRIBUTED BY (social_handle) — must match PK; can't use DISTRIBUTED RANDOMLY with PK
CREATE TABLE IF NOT EXISTS insider_threat_bronze.social_handle_map (
    social_handle       VARCHAR(100)    NOT NULL,
    employee_id         VARCHAR(10),    -- NULL = unmapped handle
    platform            VARCHAR(50)     NOT NULL,
    PRIMARY KEY (social_handle)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (social_handle);

-- =============================================================================
-- SILVER — Identity-resolved, conformed domain tables (daily grain)
-- Common lineage columns on every table, plus domain-specific fields
-- =============================================================================

-- Lineage columns macro (applied to every silver table):
--   employee_id, event_date, event_timestamp, source_domain, source_file,
--   record_hash, ingested_at, transformed_at, pipeline_version,
--   identity_resolution_status

-- Physical access control
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_pacs (
    employee_id                 VARCHAR(10)     NOT NULL,
    event_date                  DATE            NOT NULL,
    event_timestamp             TIMESTAMPTZ     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'pacs',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    -- domain fields
    door_id                     VARCHAR(20),
    location_name               VARCHAR(100),
    building_code               VARCHAR(20),
    direction                   VARCHAR(4),     -- IN | OUT
    after_hours_flag            BOOLEAN         NOT NULL DEFAULT FALSE,
    weekend_flag                BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Network events (VPN, DNS, proxy)
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_network (
    employee_id                 VARCHAR(10)     NOT NULL,
    event_date                  DATE            NOT NULL,
    event_timestamp             TIMESTAMPTZ     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'network',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    -- domain fields
    machine_id                  VARCHAR(20),
    ip_address                  VARCHAR(45),
    event_type                  VARCHAR(50),
    vpn_flag                    BOOLEAN         NOT NULL DEFAULT FALSE,
    dns_query_domain            VARCHAR(255),
    bytes_transferred           BIGINT,
    session_duration_min        FLOAT8,
    after_hours_flag            BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- DLP — file movement, USB, print
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_dlp (
    employee_id                 VARCHAR(10)     NOT NULL,
    event_date                  DATE            NOT NULL,
    event_timestamp             TIMESTAMPTZ     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'dlp',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    -- domain fields
    machine_id                  VARCHAR(20),
    event_type                  VARCHAR(50),
    file_name                   VARCHAR(255),
    file_extension              VARCHAR(20),
    file_size_mb                FLOAT8,
    destination_type            VARCHAR(50),
    usb_flag                    BOOLEAN         NOT NULL DEFAULT FALSE,
    print_flag                  BOOLEAN         NOT NULL DEFAULT FALSE,
    cloud_upload_flag           BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Communications metadata (email + Slack)
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_comms (
    employee_id                 VARCHAR(10)     NOT NULL,
    event_date                  DATE            NOT NULL,
    event_timestamp             TIMESTAMPTZ     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'comms',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    -- domain fields
    channel_type                VARCHAR(20),    -- email | slack
    recipient_count             INT,
    external_recipient_flag     BOOLEAN         NOT NULL DEFAULT FALSE,
    attachment_flag             BOOLEAN         NOT NULL DEFAULT FALSE,
    attachment_size_mb          FLOAT8,
    after_hours_flag            BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Public/social media sentiment
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_pai (
    employee_id                 VARCHAR(10)     NOT NULL,
    event_date                  DATE            NOT NULL,
    event_timestamp             TIMESTAMPTZ     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'pai',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    -- domain fields
    platform                    VARCHAR(50),
    sentiment_score             FLOAT8,         -- -1.0 to 1.0
    post_count                  INT,
    engagement_count            INT
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Geospatial building events
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_geo (
    employee_id                 VARCHAR(10)     NOT NULL,
    event_date                  DATE            NOT NULL,
    event_timestamp             TIMESTAMPTZ     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'geo',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    -- domain fields
    building_code               VARCHAR(20),
    latitude                    FLOAT8,
    longitude                   FLOAT8,
    device_type                 VARCHAR(50)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Security clearance adjudication
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_adjudication (
    employee_id                 VARCHAR(10)     NOT NULL,
    event_date                  DATE            NOT NULL,
    event_timestamp             TIMESTAMPTZ     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'adjudication',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    -- domain fields
    clearance_level             VARCHAR(20),
    clearance_status            VARCHAR(20),
    investigation_flag          BOOLEAN         NOT NULL DEFAULT FALSE,
    reinvestigation_due_date    DATE,
    status_change_flag          BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- HRIS — authoritative employee master
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_hris (
    employee_id                 VARCHAR(10)     NOT NULL,
    event_date                  DATE            NOT NULL,
    event_timestamp             TIMESTAMPTZ     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'hris',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL DEFAULT 'RESOLVED',
    -- domain fields
    full_name                   VARCHAR(200),
    department                  VARCHAR(100),
    role_title                  VARCHAR(100),
    role_peer_group             VARCHAR(50),    -- used for peer z-score grouping in Gold
    clearance_level             VARCHAR(20),
    employment_status           VARCHAR(20),    -- active | terminated | on_leave
    start_date                  DATE,
    end_date                    DATE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Dead-letter table for unresolved/partial identity records
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_unresolved_events (
    id                          SERIAL,
    source_domain               VARCHAR(50)     NOT NULL,
    source_file                 VARCHAR(255)    NOT NULL,
    raw_identifier              VARCHAR(255)    NOT NULL,   -- original native ID
    identifier_type             VARCHAR(50)     NOT NULL,   -- badge_id | machine_id | etc.
    record_hash                 VARCHAR(64)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,   -- UNRESOLVED | PARTIAL
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    raw_record                  TEXT            NOT NULL    -- JSON-serialized original row
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED RANDOMLY;

-- =============================================================================
-- GOLD — Feature derivation and MADlib anomaly scoring
-- Grain: employee_id + window_end_date (7-day rolling)
-- =============================================================================

-- Primary Gold risk feature table
CREATE TABLE IF NOT EXISTS insider_threat_gold.employee_risk_features (
    employee_id                 VARCHAR(10)     NOT NULL,
    window_end_date             DATE            NOT NULL,
    window_start_date           DATE            NOT NULL,
    -- derived features
    badge_swipes_outlier        FLOAT8,
    after_hours_pacs_score      FLOAT8,
    after_hours_network_score   FLOAT8,
    usb_exfiltration_score      FLOAT8,
    file_movement_outlier       FLOAT8,
    cloud_upload_outlier        FLOAT8,
    vpn_anomaly_score           FLOAT8,
    impossible_travel_flag      BOOLEAN         NOT NULL DEFAULT FALSE,
    comms_volume_delta          FLOAT8,
    external_comms_ratio        FLOAT8,
    sentiment_trend             FLOAT8,
    clearance_anomaly_flag      BOOLEAN         NOT NULL DEFAULT FALSE,
    cross_domain_anomaly_count  INT             NOT NULL DEFAULT 0,
    -- MADlib scoring outputs
    feature_vector              FLOAT8[],
    cluster_id                  INT,
    anomaly_score               FLOAT8,
    anomaly_percentile          FLOAT8,
    anomaly_tier                VARCHAR(10),    -- HIGH | MEDIUM | LOW
    -- lineage
    source_silver_files         TEXT[],
    model_run_id                VARCHAR(64),
    scored_at                   TIMESTAMPTZ,
    PRIMARY KEY (employee_id, window_end_date)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id)
PARTITION BY RANGE (window_end_date)
(
    START ('2026-01-01'::DATE) END ('2027-01-01'::DATE) EVERY (INTERVAL '1 month')
);

-- MADlib k-means input table (normalized feature vectors)
CREATE TABLE IF NOT EXISTS insider_threat_gold.employee_features (
    employee_id                 VARCHAR(10)     NOT NULL,
    window_end_date             DATE            NOT NULL,
    feature_vector              FLOAT8[]        NOT NULL
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Silver: speed up identity resolution joins during Silver→Gold
CREATE INDEX IF NOT EXISTS idx_sv_pacs_emp_date        ON insider_threat_silver.sv_pacs        (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_network_emp_date     ON insider_threat_silver.sv_network     (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_dlp_emp_date         ON insider_threat_silver.sv_dlp         (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_comms_emp_date       ON insider_threat_silver.sv_comms       (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_pai_emp_date         ON insider_threat_silver.sv_pai         (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_geo_emp_date         ON insider_threat_silver.sv_geo         (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_adjudication_emp     ON insider_threat_silver.sv_adjudication(employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_hris_emp             ON insider_threat_silver.sv_hris        (employee_id);

-- Bronze: mapping table joins
CREATE INDEX IF NOT EXISTS idx_asset_machine           ON insider_threat_bronze.asset_assignment (machine_id, effective_start);
CREATE INDEX IF NOT EXISTS idx_directory_slack         ON insider_threat_bronze.directory        (slack_handle);
CREATE INDEX IF NOT EXISTS idx_social_handle           ON insider_threat_bronze.social_handle_map(social_handle);

-- =============================================================================
-- BRONZE EXTERNAL TABLES — PXF → MinIO S3
-- PXF profile: s3:text (CSV with header)
-- PXF server:  minio  (config at $PXF_BASE/servers/minio/s3-site.xml)
--
-- Prerequisites (run once via SSH on GP host):
--   pxf cluster start
--   mkdir -p $PXF_BASE/servers/minio
--   cp <project>/config/pxf-minio-server/s3-site.xml $PXF_BASE/servers/minio/
--   pxf cluster sync
--   psql -d gpadmin -c "CREATE EXTENSION pxf;"
--
-- Usage: SELECT COUNT(*) FROM insider_threat_bronze.ext_hris_events;
-- Agent2 identity resolution joins these ext_* tables (pure SQL in GP).
--
-- GP does not support CREATE EXTERNAL TABLE IF NOT EXISTS — DROP first.
-- =============================================================================

-- Requires: CREATE EXTENSION pxf; (run as superuser once)

DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_hris_events;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_pacs_events;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_network_events;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_dlp_events;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_adjudication_events;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_comms_events;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_pai_events;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_geo_events;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_badge_registry;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_asset_assignment;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_directory;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_social_handle_map;

-- HRIS — authoritative employee master
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_hris_events (
    employee_id         VARCHAR(10),
    full_name           VARCHAR(200),
    department          VARCHAR(100),
    role_title          VARCHAR(200),
    role_peer_group     VARCHAR(50),
    clearance_level     VARCHAR(20),
    employment_status   VARCHAR(20),
    start_date          DATE,
    end_date            DATE
)
LOCATION ('pxf://sentinel-bronze/bronze/hris_events.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- PACS — physical access control (badge swipes)
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_pacs_events (
    badge_id            VARCHAR(20),
    event_timestamp     TIMESTAMPTZ,
    building_code       VARCHAR(20),
    door_id             VARCHAR(30),
    location_name       VARCHAR(100),
    direction           VARCHAR(4),
    after_hours         BOOLEAN,
    weekend             BOOLEAN
)
LOCATION ('pxf://sentinel-bronze/bronze/pacs_events.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Network events — VPN, DNS, proxy
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_network_events (
    machine_id              VARCHAR(20),
    ip_address              VARCHAR(45),
    event_timestamp         TIMESTAMPTZ,
    event_type              VARCHAR(50),
    vpn_flag                BOOLEAN,
    dns_query_domain        VARCHAR(255),
    bytes_transferred       BIGINT,
    session_duration_min    FLOAT8,
    after_hours             BOOLEAN
)
LOCATION ('pxf://sentinel-bronze/bronze/network_events.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- DLP — file movement, USB writes, print events
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_dlp_events (
    machine_id          VARCHAR(20),
    user_account        VARCHAR(20),
    event_timestamp     TIMESTAMPTZ,
    event_type          VARCHAR(50),
    file_name           VARCHAR(255),
    file_extension      VARCHAR(20),
    file_size_mb        FLOAT8,
    destination_type    VARCHAR(50),
    usb_flag            BOOLEAN,
    print_flag          BOOLEAN,
    cloud_upload_flag   BOOLEAN
)
LOCATION ('pxf://sentinel-bronze/bronze/dlp_events.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Adjudication — security clearance events
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_adjudication_events (
    employee_id                 VARCHAR(10),
    event_timestamp             TIMESTAMPTZ,
    clearance_level             VARCHAR(20),
    clearance_status            VARCHAR(20),
    investigation_flag          BOOLEAN,
    reinvestigation_due_date    DATE,
    status_change_flag          BOOLEAN
)
LOCATION ('pxf://sentinel-bronze/bronze/adjudication_events.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Communications metadata — email and Slack
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_comms_events (
    email_address           VARCHAR(255),
    slack_handle            VARCHAR(100),
    event_timestamp         TIMESTAMPTZ,
    channel_type            VARCHAR(20),
    recipient_count         INT,
    external_recipient_flag BOOLEAN,
    attachment_flag         BOOLEAN,
    attachment_size_mb      FLOAT8,
    after_hours             BOOLEAN
)
LOCATION ('pxf://sentinel-bronze/bronze/comms_events.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- PAI — public/social media sentiment
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_pai_events (
    social_handle       VARCHAR(100),
    event_timestamp     TIMESTAMPTZ,
    platform            VARCHAR(50),
    sentiment_score     FLOAT8,
    post_count          INT,
    engagement_count    INT
)
LOCATION ('pxf://sentinel-bronze/bronze/pai_events.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Geospatial building events
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_geo_events (
    badge_id            VARCHAR(20),
    device_id           VARCHAR(50),
    event_timestamp     TIMESTAMPTZ,
    building_code       VARCHAR(20),
    latitude            FLOAT8,
    longitude           FLOAT8,
    device_type         VARCHAR(50)
)
LOCATION ('pxf://sentinel-bronze/bronze/geo_events.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Mapping table: badge_id → employee_id
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_badge_registry (
    badge_id        VARCHAR(20),
    employee_id     VARCHAR(10),
    issued_date     DATE
)
LOCATION ('pxf://sentinel-bronze/bronze/badge_registry.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Mapping table: machine_id → employee_id (with effective dates)
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_asset_assignment (
    machine_id      VARCHAR(20),
    employee_id     VARCHAR(10),
    effective_start DATE,
    effective_end   DATE
)
LOCATION ('pxf://sentinel-bronze/bronze/asset_assignment.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Mapping table: email/slack → employee_id
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_directory (
    email_address   VARCHAR(255),
    slack_handle    VARCHAR(100),
    employee_id     VARCHAR(10)
)
LOCATION ('pxf://sentinel-bronze/bronze/directory.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Mapping table: social_handle → employee_id (~5% have NULL employee_id)
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_social_handle_map (
    social_handle   VARCHAR(100),
    employee_id     VARCHAR(10),
    platform        VARCHAR(50)
)
LOCATION ('pxf://sentinel-bronze/bronze/social_handle_map.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);
