-- =============================================================================
-- ddl.sql — Sentinel TDI Insider Threat Detection Pipeline
-- Greenplum 7.x | APPENDOPTIMIZED, zstd compression, distributed by employee_id
-- Schemas: insider_threat_bronze | insider_threat_silver | insider_threat_gold
--
-- Covers all 17 source streams:
--   Enterprise (8): HRIS, PACS, Network, DLP, Comms, PAI, Geo, Adjudication
--   Identity registers (4): Badge, Asset, Directory, Social Handle
--   External OSINT (5): Twitter, Instagram, Lifestyle, Financial Stress, Dark Web
--
-- Prerequisites (run once on GP host as superuser):
--   pxf cluster start
--   mkdir -p $PXF_BASE/servers/minio
--   cp <project>/config/pxf-minio-server/s3-site.xml $PXF_BASE/servers/minio/
--   pxf cluster sync
--   psql -d gpadmin -c "CREATE EXTENSION pxf;"
-- =============================================================================


-- =============================================================================
-- SCHEMAS
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS insider_threat_bronze;
CREATE SCHEMA IF NOT EXISTS insider_threat_silver;
CREATE SCHEMA IF NOT EXISTS insider_threat_gold;


-- =============================================================================
-- BRONZE — Regular tables (mapping / audit)
-- =============================================================================

-- Pipeline run audit
CREATE TABLE IF NOT EXISTS insider_threat_bronze.pipeline_runs (
    run_id              VARCHAR(64)     NOT NULL,
    stage_name          VARCHAR(50)     NOT NULL,
    started_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(20)     NOT NULL,
    rows_in             INT,
    rows_out            INT,
    duration_seconds    FLOAT8,
    artifacts           TEXT[],
    notes               TEXT,
    PRIMARY KEY (run_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (run_id);

-- Badge → employee_id
CREATE TABLE IF NOT EXISTS insider_threat_bronze.badge_registry (
    badge_id            VARCHAR(20)     NOT NULL,
    employee_id         VARCHAR(10)     NOT NULL,
    issued_date         DATE            NOT NULL,
    PRIMARY KEY (badge_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Machine → employee_id (with effective dates for shared workstations)
CREATE TABLE IF NOT EXISTS insider_threat_bronze.asset_assignment (
    machine_id          VARCHAR(20)     NOT NULL,
    employee_id         VARCHAR(10)     NOT NULL,
    effective_start     DATE            NOT NULL,
    effective_end       DATE,
    PRIMARY KEY (machine_id, effective_start)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (machine_id);

-- Email / Slack → employee_id
CREATE TABLE IF NOT EXISTS insider_threat_bronze.directory (
    email_address       VARCHAR(255)    NOT NULL,
    slack_handle        VARCHAR(100)    NOT NULL,
    employee_id         VARCHAR(10)     NOT NULL,
    PRIMARY KEY (email_address)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (email_address);

-- Social handle → employee_id
CREATE TABLE IF NOT EXISTS insider_threat_bronze.social_handle_map (
    social_handle       VARCHAR(100)    NOT NULL,
    employee_id         VARCHAR(10),
    platform            VARCHAR(50)     NOT NULL,
    PRIMARY KEY (social_handle)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (social_handle);

-- OSINT Bronze — Twitter/X raw feed
CREATE TABLE IF NOT EXISTS insider_threat_bronze.bronze_raw_tweets (
    tweet_id            VARCHAR(20)     NOT NULL,
    scraped_datetime    TIMESTAMPTZ     NOT NULL,
    handle              VARCHAR(100)    NOT NULL,
    tweet_text          TEXT            NOT NULL,
    retweet_flag        BOOLEAN         NOT NULL DEFAULT FALSE,
    like_count          INT             NOT NULL DEFAULT 0,
    raw_json            TEXT            NOT NULL,
    PRIMARY KEY (tweet_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (tweet_id);

-- OSINT Bronze — Instagram posts and check-ins
CREATE TABLE IF NOT EXISTS insider_threat_bronze.bronze_raw_instagram_posts (
    post_id             VARCHAR(20)     NOT NULL,
    scraped_datetime    TIMESTAMPTZ     NOT NULL,
    handle              VARCHAR(100)    NOT NULL,
    post_caption        TEXT,
    location_string     VARCHAR(255),
    location_lat        FLOAT8,
    location_lon        FLOAT8,
    post_type           VARCHAR(20)     NOT NULL,
    raw_json            TEXT            NOT NULL,
    PRIMARY KEY (post_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (post_id);

-- OSINT Bronze — Lifestyle and spending signals
CREATE TABLE IF NOT EXISTS insider_threat_bronze.bronze_raw_lifestyle_signals (
    signal_id           VARCHAR(20)     NOT NULL,
    scraped_datetime    TIMESTAMPTZ     NOT NULL,
    handle              VARCHAR(100)    NOT NULL,
    signal_source       VARCHAR(50)     NOT NULL,
    raw_text            TEXT            NOT NULL,
    estimated_value_usd INT,
    raw_json            TEXT            NOT NULL,
    PRIMARY KEY (signal_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (signal_id);

-- OSINT Bronze — Financial stress public records
CREATE TABLE IF NOT EXISTS insider_threat_bronze.bronze_raw_financial_stress (
    record_id           VARCHAR(20)     NOT NULL,
    scraped_datetime    TIMESTAMPTZ     NOT NULL,
    employee_id         VARCHAR(10)     NOT NULL,
    source              VARCHAR(50)     NOT NULL,
    raw_text            TEXT            NOT NULL,
    raw_json            TEXT            NOT NULL,
    PRIMARY KEY (record_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- OSINT Bronze — Dark web threat intelligence detections
CREATE TABLE IF NOT EXISTS insider_threat_bronze.bronze_raw_darkweb_signals (
    detection_id        VARCHAR(20)     NOT NULL,
    scraped_datetime    TIMESTAMPTZ     NOT NULL,
    handle              VARCHAR(100),
    signal_source       VARCHAR(50)     NOT NULL,
    raw_text            TEXT            NOT NULL,
    matched_on          VARCHAR(20)     NOT NULL,
    raw_json            TEXT            NOT NULL,
    PRIMARY KEY (detection_id)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (detection_id);


-- =============================================================================
-- BRONZE — External tables (PXF → MinIO S3)
-- GP does not support CREATE EXTERNAL TABLE IF NOT EXISTS — DROP first.
-- =============================================================================

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
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_tweets;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_instagram_posts;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_lifestyle_signals;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_financial_stress;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_darkweb_signals;

-- HR Master
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

-- Building Access
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

-- System Activity
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

-- Data Activity
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

-- Security Clearance
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

-- Communications
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

-- Social Sentiment
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

-- Campus Location Data
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

-- Door & Badge Register
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_badge_registry (
    badge_id        VARCHAR(20),
    employee_id     VARCHAR(10),
    issued_date     DATE
)
LOCATION ('pxf://sentinel-bronze/bronze/badge_registry.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Workstation Register
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_asset_assignment (
    machine_id      VARCHAR(20),
    employee_id     VARCHAR(10),
    effective_start DATE,
    effective_end   DATE
)
LOCATION ('pxf://sentinel-bronze/bronze/asset_assignment.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Corporate Directory
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_directory (
    email_address   VARCHAR(255),
    slack_handle    VARCHAR(100),
    employee_id     VARCHAR(10)
)
LOCATION ('pxf://sentinel-bronze/bronze/directory.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Social Media Identity Register
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_social_handle_map (
    social_handle   VARCHAR(100),
    employee_id     VARCHAR(10),
    platform        VARCHAR(50)
)
LOCATION ('pxf://sentinel-bronze/bronze/social_handle_map.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Twitter / X Activity
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_raw_tweets (
    tweet_id            VARCHAR(20),
    scraped_datetime    TIMESTAMPTZ,
    handle              VARCHAR(100),
    tweet_text          TEXT,
    retweet_flag        BOOLEAN,
    like_count          INT,
    raw_json            TEXT
)
LOCATION ('pxf://sentinel-bronze/bronze/osint/raw_tweets.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Public Location Activity
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_raw_instagram_posts (
    post_id             VARCHAR(20),
    scraped_datetime    TIMESTAMPTZ,
    handle              VARCHAR(100),
    post_caption        TEXT,
    location_string     VARCHAR(255),
    location_lat        FLOAT8,
    location_lon        FLOAT8,
    post_type           VARCHAR(20),
    raw_json            TEXT
)
LOCATION ('pxf://sentinel-bronze/bronze/osint/raw_instagram_posts.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Lifestyle Incongruity
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_raw_lifestyle_signals (
    signal_id           VARCHAR(20),
    scraped_datetime    TIMESTAMPTZ,
    handle              VARCHAR(100),
    signal_source       VARCHAR(50),
    raw_text            TEXT,
    estimated_value_usd INT,
    raw_json            TEXT
)
LOCATION ('pxf://sentinel-bronze/bronze/osint/raw_lifestyle_signals.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Financial Stress
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_raw_financial_stress (
    record_id           VARCHAR(20),
    scraped_datetime    TIMESTAMPTZ,
    employee_id         VARCHAR(10),
    source              VARCHAR(50),
    raw_text            TEXT,
    raw_json            TEXT
)
LOCATION ('pxf://sentinel-bronze/bronze/osint/raw_financial_stress.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);

-- Dark Web Alerts
CREATE READABLE EXTERNAL TABLE insider_threat_bronze.ext_raw_darkweb_signals (
    detection_id        VARCHAR(20),
    scraped_datetime    TIMESTAMPTZ,
    handle              VARCHAR(100),
    signal_source       VARCHAR(50),
    raw_text            TEXT,
    matched_on          VARCHAR(20),
    raw_json            TEXT
)
LOCATION ('pxf://sentinel-bronze/bronze/osint/raw_darkweb_signals.csv?PROFILE=s3:text&SERVER=minio')
FORMAT 'CSV' (HEADER);


-- =============================================================================
-- SILVER — Identity-resolved, conformed domain tables (daily grain)
-- =============================================================================

-- Employee Records
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
    full_name                   VARCHAR(200),
    department                  VARCHAR(100),
    role_title                  VARCHAR(100),
    role_peer_group             VARCHAR(50),
    clearance_level             VARCHAR(20),
    employment_status           VARCHAR(20),
    start_date                  DATE,
    end_date                    DATE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Building Access Events
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
    door_id                     VARCHAR(20),
    location_name               VARCHAR(100),
    building_code               VARCHAR(20),
    direction                   VARCHAR(4),
    after_hours_flag            BOOLEAN         NOT NULL DEFAULT FALSE,
    weekend_flag                BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- System Activity Events
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

-- Data Activity Events
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

-- Communications Events
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
    channel_type                VARCHAR(20),
    recipient_count             INT,
    external_recipient_flag     BOOLEAN         NOT NULL DEFAULT FALSE,
    attachment_flag             BOOLEAN         NOT NULL DEFAULT FALSE,
    attachment_size_mb          FLOAT8,
    after_hours_flag            BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Social Sentiment
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
    platform                    VARCHAR(50),
    sentiment_score             FLOAT8,
    post_count                  INT,
    engagement_count            INT,
    emotion_tags                TEXT[],
    keyword_flags               TEXT[]
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Campus Location Events
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
    building_code               VARCHAR(20),
    latitude                    FLOAT8,
    longitude                   FLOAT8,
    device_type                 VARCHAR(50)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Security Clearance Events
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
    clearance_level             VARCHAR(20),
    clearance_status            VARCHAR(20),
    investigation_flag          BOOLEAN         NOT NULL DEFAULT FALSE,
    reinvestigation_due_date    DATE,
    status_change_flag          BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Unlinked Event Log (audit / dead-letter)
CREATE TABLE IF NOT EXISTS insider_threat_silver.sv_unresolved_events (
    id                          SERIAL,
    source_domain               VARCHAR(50)     NOT NULL,
    source_file                 VARCHAR(255)    NOT NULL,
    raw_identifier              VARCHAR(255)    NOT NULL,
    identifier_type             VARCHAR(50)     NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    raw_record                  TEXT            NOT NULL
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED RANDOMLY;

-- Location Anomalies (OSINT — Instagram check-ins)
CREATE TABLE IF NOT EXISTS insider_threat_silver.silver_geo_anomalies (
    post_id                     VARCHAR(20)     NOT NULL,
    event_date                  DATE            NOT NULL,
    employee_id                 VARCHAR(10)     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'instagram',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    classified_location_type    VARCHAR(30)     NOT NULL,
    anomaly_flag                BOOLEAN         NOT NULL DEFAULT FALSE,
    work_hours_flag             BOOLEAN         NOT NULL DEFAULT FALSE,
    incongruity_flag            BOOLEAN         NOT NULL DEFAULT FALSE
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Lifestyle Risk Signals (OSINT)
CREATE TABLE IF NOT EXISTS insider_threat_silver.silver_lifestyle_incongruity (
    signal_id                   VARCHAR(20)     NOT NULL,
    event_date                  DATE            NOT NULL,
    employee_id                 VARCHAR(10)     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'lifestyle',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    signal_type                 VARCHAR(30)     NOT NULL,
    estimated_value_usd         INT,
    salary_band                 VARCHAR(10)     NOT NULL,
    incongruity_score           FLOAT8          NOT NULL,
    cumulative_30day_spend      INT             NOT NULL DEFAULT 0
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Financial Stress Records (OSINT)
CREATE TABLE IF NOT EXISTS insider_threat_silver.silver_financial_stress (
    record_id                   VARCHAR(20)     NOT NULL,
    event_date                  DATE            NOT NULL,
    employee_id                 VARCHAR(10)     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'financial_stress',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL DEFAULT 'RESOLVED',
    record_type                 VARCHAR(30)     NOT NULL,
    amount_usd                  INT,
    stress_score                FLOAT8          NOT NULL,
    cumulative_stress_score     FLOAT8          NOT NULL
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Dark Web Detections (OSINT)
CREATE TABLE IF NOT EXISTS insider_threat_silver.silver_darkweb_signals (
    detection_id                VARCHAR(20)     NOT NULL,
    event_date                  DATE            NOT NULL,
    employee_id                 VARCHAR(10)     NOT NULL,
    source_domain               VARCHAR(50)     NOT NULL DEFAULT 'darkweb',
    source_file                 VARCHAR(255)    NOT NULL,
    record_hash                 VARCHAR(64)     NOT NULL,
    ingested_at                 TIMESTAMPTZ     NOT NULL,
    transformed_at              TIMESTAMPTZ     NOT NULL,
    pipeline_version            VARCHAR(20)     NOT NULL,
    identity_resolution_status  VARCHAR(20)     NOT NULL,
    signal_type                 VARCHAR(30)     NOT NULL,
    severity                    VARCHAR(10)     NOT NULL,
    confidence_score            FLOAT8          NOT NULL,
    matched_on                  VARCHAR(20)     NOT NULL
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);


-- =============================================================================
-- GOLD — Feature derivation, peer group scoring, and weekly risk scores
-- =============================================================================

-- Behavioral Risk Profile (internal — 7-day rolling window)
CREATE TABLE IF NOT EXISTS insider_threat_gold.employee_risk_features (
    employee_id                 VARCHAR(10)     NOT NULL,
    window_end_date             DATE            NOT NULL,
    window_start_date           DATE            NOT NULL,
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
    feature_vector              FLOAT8[],
    cluster_id                  INT,
    anomaly_score               FLOAT8,
    anomaly_percentile          FLOAT8,
    anomaly_tier                VARCHAR(10),
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

-- Scoring Input Vectors (peer group model input)
CREATE TABLE IF NOT EXISTS insider_threat_gold.employee_features (
    employee_id                 VARCHAR(10)     NOT NULL,
    window_end_date             DATE            NOT NULL,
    feature_vector              FLOAT8[]        NOT NULL
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Social Sentiment Risk (weekly — OSINT Twitter stream)
CREATE TABLE IF NOT EXISTS insider_threat_gold.gold_twitter_risk (
    week_start_date         DATE            NOT NULL,
    employee_id             VARCHAR(10)     NOT NULL,
    sentiment_trend         VARCHAR(20)     NOT NULL,
    sentiment_risk_score    FLOAT8          NOT NULL,
    primary_emotion         VARCHAR(50),
    risk_narrative          TEXT,
    scored_at               TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (employee_id, week_start_date)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Location Risk (weekly — OSINT Instagram stream)
CREATE TABLE IF NOT EXISTS insider_threat_gold.gold_location_risk (
    week_start_date             DATE            NOT NULL,
    employee_id                 VARCHAR(10)     NOT NULL,
    sensitive_location_count    INT             NOT NULL DEFAULT 0,
    work_hours_absence_count    INT             NOT NULL DEFAULT 0,
    location_risk_score         FLOAT8          NOT NULL,
    risk_narrative              TEXT,
    scored_at                   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (employee_id, week_start_date)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Lifestyle Risk (weekly — OSINT spending stream)
CREATE TABLE IF NOT EXISTS insider_threat_gold.gold_lifestyle_risk (
    week_start_date             DATE            NOT NULL,
    employee_id                 VARCHAR(10)     NOT NULL,
    incongruity_event_count     INT             NOT NULL DEFAULT 0,
    cumulative_30day_spend      INT             NOT NULL DEFAULT 0,
    max_incongruity_score       FLOAT8          NOT NULL DEFAULT 0.0,
    lifestyle_risk_score        FLOAT8          NOT NULL,
    risk_narrative              TEXT,
    scored_at                   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (employee_id, week_start_date)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Financial Stress Risk (weekly — OSINT public records stream)
CREATE TABLE IF NOT EXISTS insider_threat_gold.gold_financial_stress_risk (
    week_start_date             DATE            NOT NULL,
    employee_id                 VARCHAR(10)     NOT NULL,
    active_record_count         INT             NOT NULL DEFAULT 0,
    cumulative_stress_score     FLOAT8          NOT NULL DEFAULT 0.0,
    financial_risk_score        FLOAT8          NOT NULL,
    risk_narrative              TEXT,
    scored_at                   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (employee_id, week_start_date)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Dark Web Risk (weekly — OSINT breach intelligence stream)
CREATE TABLE IF NOT EXISTS insider_threat_gold.gold_darkweb_risk (
    week_start_date             DATE            NOT NULL,
    employee_id                 VARCHAR(10)     NOT NULL,
    detection_count             INT             NOT NULL DEFAULT 0,
    max_severity                FLOAT8          NOT NULL DEFAULT 0.0,
    darkweb_risk_score          FLOAT8          NOT NULL,
    risk_narrative              TEXT,
    scored_at                   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (employee_id, week_start_date)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);

-- Composite Risk Score — all 6 streams fused
-- Weights: internal_behavioral=0.25, financial=0.18, twitter=0.15,
--          lifestyle=0.15, darkweb=0.15, location=0.12
CREATE TABLE IF NOT EXISTS insider_threat_gold.gold_composite_risk (
    week_start_date                 DATE            NOT NULL,
    employee_id                     VARCHAR(10)     NOT NULL,
    twitter_risk_score              FLOAT8          NOT NULL DEFAULT 0.0,
    location_risk_score             FLOAT8          NOT NULL DEFAULT 0.0,
    lifestyle_risk_score            FLOAT8          NOT NULL DEFAULT 0.0,
    financial_risk_score            FLOAT8          NOT NULL DEFAULT 0.0,
    darkweb_risk_score              FLOAT8          NOT NULL DEFAULT 0.0,
    internal_behavioral_risk_score  FLOAT8          NOT NULL DEFAULT 0.0,
    composite_risk_score            FLOAT8          NOT NULL,
    risk_tier                       VARCHAR(10)     NOT NULL,
    tier_change_flag                BOOLEAN         NOT NULL DEFAULT FALSE,
    primary_signal_driver           VARCHAR(30),
    recommended_action              VARCHAR(15)     NOT NULL,
    composite_narrative             TEXT,
    scored_at                       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (employee_id, week_start_date)
)
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id);


-- =============================================================================
-- INDEXES
-- =============================================================================

-- Silver — enterprise domains
CREATE INDEX IF NOT EXISTS idx_sv_hris_emp             ON insider_threat_silver.sv_hris         (employee_id);
CREATE INDEX IF NOT EXISTS idx_sv_pacs_emp_date        ON insider_threat_silver.sv_pacs         (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_network_emp_date     ON insider_threat_silver.sv_network      (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_dlp_emp_date         ON insider_threat_silver.sv_dlp          (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_comms_emp_date       ON insider_threat_silver.sv_comms        (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_pai_emp_date         ON insider_threat_silver.sv_pai          (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_geo_emp_date         ON insider_threat_silver.sv_geo          (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_sv_adjudication_emp     ON insider_threat_silver.sv_adjudication (employee_id, event_date);

-- Silver — OSINT domains
CREATE INDEX IF NOT EXISTS idx_silver_geo_emp_date       ON insider_threat_silver.silver_geo_anomalies        (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_silver_lifestyle_emp_date ON insider_threat_silver.silver_lifestyle_incongruity (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_silver_fin_emp_date       ON insider_threat_silver.silver_financial_stress      (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_silver_dw_emp_date        ON insider_threat_silver.silver_darkweb_signals       (employee_id, event_date);

-- Bronze — identity register joins
CREATE INDEX IF NOT EXISTS idx_asset_machine           ON insider_threat_bronze.asset_assignment  (machine_id, effective_start);
CREATE INDEX IF NOT EXISTS idx_directory_slack         ON insider_threat_bronze.directory         (slack_handle);
CREATE INDEX IF NOT EXISTS idx_social_handle           ON insider_threat_bronze.social_handle_map (social_handle);

-- Gold — all risk tables
CREATE INDEX IF NOT EXISTS idx_gold_features_emp       ON insider_threat_gold.employee_risk_features  (employee_id, window_end_date);
CREATE INDEX IF NOT EXISTS idx_gold_twitter_emp        ON insider_threat_gold.gold_twitter_risk        (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_location_emp       ON insider_threat_gold.gold_location_risk       (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_lifestyle_emp      ON insider_threat_gold.gold_lifestyle_risk      (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_financial_emp      ON insider_threat_gold.gold_financial_stress_risk (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_darkweb_emp        ON insider_threat_gold.gold_darkweb_risk        (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_composite_emp      ON insider_threat_gold.gold_composite_risk      (employee_id, week_start_date);
