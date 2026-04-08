-- =============================================================================
-- ddl_osint.sql — OSINT Augmentation Tables
-- 5 streams: Twitter, Instagram, Lifestyle, Financial Stress, Dark Web
-- Bronze (raw) -> Silver (classified) -> Gold (weekly risk scores)
-- Run AFTER ddl.sql — depends on schemas already existing
-- =============================================================================

-- =============================================================================
-- BRONZE OSINT — Raw scraper / feed tables
-- =============================================================================

-- Twitter/X raw scraper output
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

-- Instagram raw post/check-in output
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

-- Lifestyle / luxury purchase signals (public records + social proxies)
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

-- Financial stress public record proxies (name-matched to HR Master)
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

-- Dark web threat intel feed detections
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
-- BRONZE EXTERNAL TABLES — OSINT PXF -> MinIO S3 (bronze/osint/ prefix)
-- =============================================================================

DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_tweets;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_instagram_posts;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_lifestyle_signals;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_financial_stress;
DROP EXTERNAL TABLE IF EXISTS insider_threat_bronze.ext_raw_darkweb_signals;

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
-- SILVER OSINT — Identity-resolved, classified domain tables
-- =============================================================================

-- Twitter Silver: augment existing sv_pai with emotion_tags + keyword_flags
ALTER TABLE insider_threat_silver.sv_pai
    ADD COLUMN IF NOT EXISTS emotion_tags   TEXT[],
    ADD COLUMN IF NOT EXISTS keyword_flags  TEXT[];

-- Instagram -> location anomaly classification
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

-- Lifestyle signals -> incongruity scoring
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

-- Financial stress -> public record classification
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

-- Dark web -> threat intel signal classification
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
-- GOLD OSINT — Weekly risk scores per stream (employee_id + week_start_date)
-- =============================================================================

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

-- =============================================================================
-- GOLD COMPOSITE — Fusion of all 6 streams (internal + 5 OSINT)
-- Weights: internal_behavioral=0.25, financial=0.18, twitter=0.15,
--          lifestyle=0.15, darkweb=0.15, location=0.12
-- =============================================================================

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
-- INDEXES — OSINT Silver + Gold
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_silver_geo_emp_date       ON insider_threat_silver.silver_geo_anomalies        (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_silver_lifestyle_emp_date ON insider_threat_silver.silver_lifestyle_incongruity (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_silver_fin_emp_date       ON insider_threat_silver.silver_financial_stress      (employee_id, event_date);
CREATE INDEX IF NOT EXISTS idx_silver_dw_emp_date        ON insider_threat_silver.silver_darkweb_signals       (employee_id, event_date);

CREATE INDEX IF NOT EXISTS idx_gold_twitter_emp          ON insider_threat_gold.gold_twitter_risk              (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_location_emp         ON insider_threat_gold.gold_location_risk             (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_lifestyle_emp        ON insider_threat_gold.gold_lifestyle_risk            (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_financial_emp        ON insider_threat_gold.gold_financial_stress_risk     (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_darkweb_emp          ON insider_threat_gold.gold_darkweb_risk              (employee_id, week_start_date);
CREATE INDEX IF NOT EXISTS idx_gold_composite_emp        ON insider_threat_gold.gold_composite_risk            (employee_id, week_start_date);
