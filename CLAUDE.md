# CLAUDE.md — Insider Threat Synthetic Data Pipeline
## Tanzu Data Intelligence Demo | Modern Data Warehouse + Classical ML Story

---

## Project Purpose

This project demonstrates the Tanzu Data Intelligence (TDI) stack as a unified
modern data warehouse platform for insider threat detection. It targets enterprise
and federal audiences and uses a Medallion architecture (Bronze → Silver → Gold)
orchestrated via Apache Airflow, deployed on Greenplum 7.x

### Demo Narrative Arc

> "Classical ML finds the signal. The data warehouse is the inference engine.
> Generative AI explains it to the analyst."

- **Bronze** — Raw synthetic data generation. Source-native formats. No identity
  resolution. No derived features. No threat labels.
- **Silver** — Identity resolution and structural conformance. Every record gets
  `employee_id` as the common spine. Lineage on every row. Daily grain.
- **Gold** — Feature derivation and anomaly scoring. Rolling 7-day window grain.
  MADlib k-means produces an anomaly score per employee per window. Threat
  determination is a derived ML output, not a seeded label.

Classical ML (MADlib unsupervised) handles pattern recognition at scale inside
Greenplum — no external model server, compute goes to the data. This is the
"AI at the data layer" proof point for TDI. The anomaly score is intentionally
designed as an input feature for a future generative AI / RAG explanation layer
(the Sovereign AI story).

---

## Tech Stack

| Component       | Version / Detail                                             |
|---|---|
| Greenplum       | 7.x — APPENDOPTIMIZED, zstd compression, distributed tables |
| Python          | 3.11                                                         |
| Faker           | Latest stable — all synthetic PII generation                 |
| Pandas          | Bronze generation and Silver transformation                  |
| PyArrow         | Parquet serialization for Silver and Gold                    |
| psycopg2        | Greenplum connectivity from Python                           |
| Apache Airflow  | TaskFlow API — batch orchestration across all layers         |
| MADlib          | Unsupervised anomaly detection (k-means + LOF callout)       |
| PostGIS         | Available in Greenplum for geospatial enrichment             |

---

## Global Data Contract

```python
RANDOM_SEED       = 42
EMPLOYEE_COUNT    = 500
EMPLOYEE_ID_FMT   = "EMP_{n:05d}"    # EMP_00001 through EMP_00500
TIMELINE_DAYS     = 90
DATE_FORMAT       = "ISO-8601"        # all timestamps UTC
NO_REAL_PII       = True              # Faker only — no real names, emails, SSNs
ROLLING_WINDOW    = 7                 # days — Gold layer grain
GOLD_SCHEMA       = "insider_threat_gold"
SILVER_SCHEMA     = "insider_threat_silver"
BRONZE_SCHEMA     = "insider_threat_bronze"
```

---

## Medallion Layer Definitions

---

### Bronze — Raw Synthetic Data

**Purpose:** Generate realistic raw event data in source-native formats.
No `employee_id` in non-HR sources — each source uses its own native identifier,
exactly as a real enterprise source system would. No derived features. No threat
labels. Preserve source realism including noise, missing fields, and format quirks.

Also generates reference/mapping tables that Silver uses for identity resolution.

**Output location:** `/data/bronze/`

#### Domain Files

| File | Format | Native Identifier | Description |
|---|---|---|---|
| `hris_events.csv` | CSV | `employee_id` | Authoritative employee master — org, role, clearance level, start/end date |
| `pacs_events.json` | JSON | `badge_id` | Physical building access — door ID, timestamp, direction (IN/OUT) |
| `dlp_events.json` | JSON | `machine_id`, `user_account` | File movement, USB write events, print events |
| `network_events.json` | JSON | `machine_id`, `ip_address` | VPN logins, DNS queries, proxy logs, session duration |
| `adjudication_events.csv` | CSV | `employee_id` | Security clearance status, periodic reinvestigation flags |
| `comms_events.csv` | CSV | `email_address`, `slack_handle` | Email and Slack metadata — no body content, recipient counts, attachment flags |
| `pai_events.csv` | CSV | `social_handle` | Social media sentiment scores, post frequency |
| `geo_events.json` | JSON | `badge_id`, `device_id` | Geospatial building mapping, location timestamps |

#### Mapping Tables (Bronze artifacts consumed by Silver)

| File | Format | Maps |
|---|---|---|
| `asset_assignment.csv` | CSV | `machine_id → employee_id` with effective_start, effective_end dates |
| `badge_registry.csv` | CSV | `badge_id → employee_id` |
| `directory.csv` | CSV | `email_address, slack_handle → employee_id` |
| `social_handle_map.csv` | CSV | `social_handle → employee_id` — multi-platform: twitter (100%), instagram (~70%), linkedin (~50%). ~5% unmapped ghost handles for realism |

#### Synthetic Data Characteristics

- 500 employees, 90-day timeline, RANDOM_SEED=42, Faker for all PII
- Inject realistic behavioral variance — some employees naturally noisy (frequent
  after-hours work, heavy file movement for legitimate reasons), some clean
- Do NOT inject explicit threat signals or labels — MADlib must find the signal
- Include realistic noise: missed badge swipes, shared workstations, travel days,
  VPN from home, legitimate after-hours work
- A small cohort (~25 employees) should have statistically separable behavior
  across multiple domains simultaneously — elevated after-hours access AND unusual
  file movement AND sentiment decline — without any explicit flag marking them
- Schema documentation: `schema/bronze_schema_map.json`

---

### Silver — Identity Resolution and Structural Conformance

**Purpose:** Resolve all source-native identifiers to `employee_id`. Normalize
and conform each domain into structured Greenplum tables. One table per domain.
Daily grain (`employee_id + event_date`). No cross-domain joins yet. No derived
features. Full lineage on every record.

**Key principle:** Identity resolution happens here and only here. Every Silver
table has `employee_id` as the common spine so Gold can join across domains cleanly.

#### Identity Resolution by Domain

| Silver Table | Resolution Path |
|---|---|
| `sv_hris` | Direct — HRIS is the authoritative `employee_id` source |
| `sv_pacs` | `badge_id → employee_id` via `badge_registry` |
| `sv_dlp` | `machine_id → employee_id` via `asset_assignment` |
| `sv_network` | `machine_id → employee_id` via `asset_assignment` (handle shared machines — most recent assignment wins) |
| `sv_adjudication` | Direct — uses `employee_id` natively |
| `sv_comms` | `email_address → employee_id` via `directory` |
| `sv_pai` | `social_handle → employee_id` via `social_handle_map` |
| `sv_geo` | `badge_id → employee_id` via `badge_registry` |

Records that cannot be resolved get `identity_resolution_status = 'UNRESOLVED'`
and are written to `sv_unresolved_events` (dead letter table) for lineage reporting.
Partial resolution (e.g. machine mapped but no current employee assignment) gets
`identity_resolution_status = 'PARTIAL'`.

#### Required Lineage Columns on Every Silver Table

```sql
employee_id                VARCHAR(10)    NOT NULL  -- resolved common spine
event_date                 DATE           NOT NULL  -- UTC date
event_timestamp            TIMESTAMPTZ    NOT NULL  -- UTC full precision
source_domain              VARCHAR(50)    NOT NULL  -- 'pacs' | 'network' | 'dlp' | etc.
source_file                VARCHAR(255)   NOT NULL  -- Bronze filename
record_hash                VARCHAR(64)    NOT NULL  -- SHA-256 of raw record content
ingested_at                TIMESTAMPTZ    NOT NULL  -- when Bronze file was generated
transformed_at             TIMESTAMPTZ    NOT NULL  -- when Silver transform ran
pipeline_version           VARCHAR(20)    NOT NULL  -- Airflow DAG run ID
identity_resolution_status VARCHAR(20)   NOT NULL  -- RESOLVED | UNRESOLVED | PARTIAL
```

#### Domain-Specific Conformed Fields (beyond lineage columns)

`sv_pacs`:
```
door_id, location_name, building_code, direction,
after_hours_flag, weekend_flag
```

`sv_network`:
```
machine_id, ip_address, event_type, vpn_flag,
dns_query_domain, bytes_transferred, session_duration_min,
after_hours_flag
```

`sv_dlp`:
```
machine_id, event_type, file_name, file_extension,
file_size_mb, destination_type, usb_flag, print_flag,
cloud_upload_flag
```

`sv_comms`:
```
channel_type, recipient_count, external_recipient_flag,
attachment_flag, attachment_size_mb, after_hours_flag
```

`sv_pai`:
```
platform, sentiment_score, post_count, engagement_count,
emotion_tags, keyword_flags
```

`sv_geo`:
```
building_code, latitude, longitude, device_type
```

`sv_adjudication`:
```
clearance_level, clearance_status, investigation_flag,
reinvestigation_due_date, status_change_flag
```

**Output location:** Greenplum Silver schema + `/data/silver/*.parquet`
**Schema documentation:** `schema/silver_lineage_map.json`

---

### Gold — Feature Derivation and Anomaly Scoring

**Purpose:** Join all Silver tables on `employee_id`. Derive behavioral features
from cross-domain patterns. Score each employee per rolling window using MADlib
k-means. Threat determination is a derived ML output — not a rule and not a label.

**Grain:** `employee_id + window_end_date` (7-day rolling window)

This grain is intentionally different from Silver's daily grain to demonstrate
the analytical value of time-windowed aggregation in a modern data warehouse.

#### Feature Derivation

All features are derived — no raw event data in Gold.

| Feature | Source Domain(s) | Derivation |
|---|---|---|
| `badge_swipes_outlier` | sv_pacs | Employee window swipe count vs. role-peer z-score |
| `after_hours_pacs_score` | sv_pacs | After-hours badge events normalized by role baseline |
| `after_hours_network_score` | sv_network | After-hours network sessions normalized by role baseline |
| `usb_exfiltration_score` | sv_dlp | USB write volume vs. employee 30-day rolling baseline |
| `file_movement_outlier` | sv_dlp | File move/copy event count vs. peer group z-score |
| `cloud_upload_outlier` | sv_dlp | Cloud upload volume vs. peer group |
| `vpn_anomaly_score` | sv_network | VPN logins from unusual hours or high-frequency bursts |
| `impossible_travel_flag` | sv_pacs, sv_geo | Two locations physically impossible within time delta |
| `comms_volume_delta` | sv_comms | Week-over-week change in total message volume |
| `external_comms_ratio` | sv_comms | Ratio of external recipients to total recipients |
| `sentiment_trend` | sv_pai | 7-day rolling avg sentiment vs. 30-day personal baseline |
| `clearance_anomaly_flag` | sv_adjudication | Any reinvestigation flag or status change in window |
| `cross_domain_anomaly_count` | All | Count of domains with any outlier flag in this window |

#### MADlib Anomaly Scoring

Primary algorithm: K-means clustering on normalized feature vector.
Distance from assigned cluster centroid = anomaly score.
High distance = behaviorally unusual relative to peer cluster.

```sql
-- Prepare normalized feature table
CREATE TABLE insider_threat_gold.employee_features AS
SELECT
    employee_id,
    window_end_date,
    ARRAY[
        badge_swipes_outlier,
        after_hours_pacs_score,
        after_hours_network_score,
        usb_exfiltration_score,
        file_movement_outlier,
        vpn_anomaly_score,
        comms_volume_delta,
        sentiment_trend,
        cross_domain_anomaly_count::FLOAT8
    ] AS feature_vector
FROM insider_threat_gold.employee_risk_features
WITH (appendoptimized=true, compresstype=zstd)
DISTRIBUTED BY (employee_id);

-- Train k-means (k=5 clusters)
SELECT madlib.kmeans(
    'insider_threat_gold.employee_features',
    'feature_vector',
    5,
    'madlib.squared_dist_norm2',
    'madlib.avg',
    20,
    0.001
);

-- Score: distance from centroid = anomaly_score
```

Production callout (for demo narrative): MADlib LOF (`madlib.lof`) provides
local outlier factor scoring — more sensitive to local density variations,
better for sparse anomalous populations. K-means is used here for interpretability
and visual cluster separation in the demo.

#### Gold Output Columns

```sql
employee_id                VARCHAR(10)    NOT NULL
window_end_date            DATE           NOT NULL
window_start_date          DATE           NOT NULL   -- window_end_date - 6
feature_vector             FLOAT8[]       NOT NULL   -- normalized feature array
cluster_id                 INT            NOT NULL   -- MADlib k-means assignment
anomaly_score              FLOAT8         NOT NULL   -- distance from centroid
anomaly_percentile         FLOAT8         NOT NULL   -- percentile rank 0-100
anomaly_tier               VARCHAR(10)    NOT NULL   -- HIGH | MEDIUM | LOW
cross_domain_anomaly_count INT            NOT NULL
[all derived features listed above]
source_silver_files        TEXT[]         NOT NULL   -- lineage: Silver files contributing
model_run_id               VARCHAR(64)    NOT NULL   -- MADlib model version identifier
scored_at                  TIMESTAMPTZ    NOT NULL
```

**Output location:** Greenplum Gold schema + `/data/gold/employee_risk_features.parquet`
**Schema documentation:** `schema/feature_dictionary.json`

---

## Airflow DAG Design

**File:** `dags/insider_threat_dag.py`
**API:** TaskFlow API (`@task` decorators, `expand_kwargs` for parallel Silver)
**Schedule:** `@daily`

```
s1_generate (Bronze: 8 internal + 5 OSINT streams)
  └── s2_resolve_domain × 8 (internal Silver, parallel)
        └── s2_collect_internal (fan-in)
              └── s2_resolve_domain × 5 (OSINT Silver, parallel)
                    └── s3_score (internal MADlib + 5 OSINT Gold tables + composite)
                          └── s5_validate
                                └── s6_report
```

Internal Silver domains run in parallel after Bronze. OSINT Silver runs after
internal Silver completes (osint_lifestyle joins sv_hris). Gold runs after all
13 Silver domains are populated.

Each task must:
- Log input row count on entry, output row count on exit
- Write a lineage record to `insider_threat_bronze.pipeline_runs`
- Raise `AirflowException` if identity resolution rate falls below threshold
  (90% for internal domains, 30% for OSINT domains)
- Raise `AirflowException` if output row count is zero

---

## Greenplum DDL Rules

All fact tables:
```sql
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
DISTRIBUTED BY (employee_id)
```

Gold table additionally partitioned:
```sql
PARTITION BY RANGE (window_end_date)
(START ('2026-01-01') END ('2027-01-01') EVERY (INTERVAL '1 month'))
```

All timestamp columns: `TIMESTAMP WITH TIME ZONE`

Schema layout:
```
insider_threat_bronze   -- mapping tables + pipeline_runs audit table
insider_threat_silver   -- sv_* domain tables + sv_unresolved_events
insider_threat_gold     -- employee_risk_features + employee_features (MADlib input)
```

---

## File and Directory Structure

```
Sentinel-TDI/
├── CLAUDE.md
├── requirements.txt                    # Python dependencies
├── .env.example                        # Environment variable template
│
├── scripts/
│   ├── s1_generate_raw.py              # Bronze — synthetic data generation (8 internal + 5 OSINT)
│   ├── generate_osint_streams.py       # OSINT Bronze sub-generator (called by s1)
│   ├── s2_transform_silver.py          # Silver — identity resolution + conformance
│   ├── s3_score_gold.py                # Gold — feature derivation + MADlib scoring
│   ├── s5_validate_pipeline.py         # QA — coverage, resolution rates, lineage checks
│   ├── s6_report_analytics.py          # Report — executive analytics and validation reports
│   ├── s7_setup_superset.py            # Dashboard — Superset catalog setup
│   └── db.py                           # Shared Greenplum connection helper
│
├── data/
│   ├── bronze/                         # Raw synthetic files (CSV, JSON) — created at runtime
│   │   └── osint/                      # OSINT Bronze stream files (5 streams)
│   ├── silver/                         # Parquet outputs per domain — created at runtime
│   └── gold/                           # Parquet risk feature table — created at runtime
│
├── ddl/
│   └── ddl.sql                         # All Greenplum DDL — Bronze + Silver + Gold (internal + OSINT)
│
├── dags/
│   └── insider_threat_dag.py           # Airflow TaskFlow DAG (runnable, @daily)
│
├── sql/
│   ├── madlib_train.sql                # MADlib k-means training
│   ├── madlib_score.sql                # Anomaly scoring and percentile ranking
│   └── analytics_queries.sql          # Dashboard analytics queries
│
├── config/
│   └── pxf-minio-server/
│       └── s3-site.xml.example         # PXF → MinIO config template (fill in credentials)
│
├── schema/                             # Generated schema documentation — created at runtime
└── reports/                            # Generated validation and analytics reports — created at runtime
```

---

## Script Execution Order

```
s1_generate_raw      (Bronze — no deps)
  └─► s2_transform_silver × 8 internal  (Silver — parallel)
        └─► s2_transform_silver × 5 OSINT  (Silver — parallel, after internal)
              └─► s3_score_gold          (Gold — MADlib + OSINT stream tables)
                    └─► s5_validate_pipeline
                          └─► s6_report_analytics
```

Each script is independently runnable:
```bash
cd scripts
python s1_generate_raw.py
python s2_transform_silver.py
python s3_score_gold.py
python s5_validate_pipeline.py
python s6_report_analytics.py
```

---

## Validation Targets

| Check | Target |
|---|---|
| Employee coverage in Gold | All 500 EMP IDs present |
| Silver identity resolution rate | ≥ 90% internal, ≥ 30% OSINT domains |
| Unresolved records | Written to `sv_unresolved_events`, count reported |
| Timeline coverage | 90-day window, no gaps for active employees |
| Gold window coverage | Every employee has ≥ 12 rolling windows |
| Feature null rate | < 2% per feature column |
| Anomaly score distribution | Non-degenerate — at least 3 populated clusters |
| Lineage traceability | Every Gold record traces back to a Silver source file |
| MADlib model metadata | `model_run_id` logged in `pipeline_runs` |
| Cross-domain coverage | All 8 domains contributing to at least 95% of Gold records |

---

## Coding Standards

- Python 3.11, type hints, docstrings on all public functions
- Logging via `logging` module, INFO level default, include row counts
- All config from environment variables:

```python
import os
RANDOM_SEED          = int(os.getenv("RANDOM_SEED", 42))
EMPLOYEE_COUNT       = int(os.getenv("EMPLOYEE_COUNT", 500))
TIMELINE_DAYS        = int(os.getenv("TIMELINE_DAYS", 90))
TIMELINE_START_DATE  = os.getenv("TIMELINE_START_DATE", "2026-01-01")
GP_HOST              = os.getenv("GP_HOST", "localhost")
GP_PORT              = int(os.getenv("GP_PORT", 5432))
GP_DB                = os.getenv("GP_DB", "gpadmin")
GP_USER              = os.getenv("GP_USER", "gpadmin")
GP_PASSWORD          = os.getenv("GP_PASSWORD", "")
MINIO_ENDPOINT       = os.getenv("MINIO_ENDPOINT", "http://localhost:9000")
MINIO_ACCESS_KEY     = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY     = os.getenv("MINIO_SECRET_KEY", "")
MINIO_BUCKET         = os.getenv("MINIO_BUCKET", "sentinel-bronze")
SUPERSET_URL         = os.getenv("SUPERSET_URL")         # s7 only
SUPERSET_USER        = os.getenv("SUPERSET_USER")        # s7 only
SUPERSET_PASSWORD    = os.getenv("SUPERSET_PASSWORD")    # s7 only
```

- No hardcoded file paths — use `pathlib.Path` relative to project root
- All Greenplum operations via psycopg2 with connection pooling
- All code must be runnable against Greenplum 7.x

---

## Reference Material

- Kaggle insider threat notebook (use for MADlib and feature engineering patterns,
  extend to all 8 source domains — the notebook is incomplete):
  https://www.kaggle.com/code/sumedh1507/insider-threat-insights/notebook
- CERT Insider Threat Dataset v6.2 — behavioral signal patterns for Bronze generation
- MADlib documentation: https://madlib.apache.org/docs/latest/
- Greenplum 7.x documentation for APPENDOPTIMIZED table syntax
-Approach to Generating Insider Threat Data https://ieeexplore.ieee.org/document/6565236

---

## OSINT Augmentation — 5 External Behavioral Streams

These 5 OSINT streams augment the 12 internal enterprise tables, adding external
behavioral signal to the composite risk score. Each stream follows the same
Bronze → Silver → Gold medallion pattern.

### DDL

All OSINT DDL is consolidated in `ddl/ddl.sql` alongside internal tables:
- 5 Bronze regular tables + 5 ext_* PXF external tables (path: `bronze/osint/`)
- sv_pai includes `emotion_tags TEXT[]` and `keyword_flags TEXT[]` natively
- 4 new Silver tables + 5 Gold stream tables + `gold_composite_risk`

### Bronze OSINT Streams

| File | MinIO Path | Native ID | Description |
|---|---|---|---|
| `raw_tweets.csv` | `bronze/osint/raw_tweets.csv` | `handle` (social_handle) | Tweet text, retweet flag, like count |
| `raw_instagram_posts.csv` | `bronze/osint/raw_instagram_posts.csv` | `handle` (social_handle) | Post caption, location lat/lon, post type |
| `raw_lifestyle_signals.csv` | `bronze/osint/raw_lifestyle_signals.csv` | `handle` (social_handle) | Signal source, estimated_value_usd |
| `raw_financial_stress.csv` | `bronze/osint/raw_financial_stress.csv` | `employee_id` (direct) | Source, raw public record text |
| `raw_darkweb_signals.csv` | `bronze/osint/raw_darkweb_signals.csv` | `handle` (email OR social) | Signal source, matched_on (email\|social_handle) |

### Silver OSINT Tables

| Table | Resolution Path | Key Columns |
|---|---|---|
| sv_pai (augmented) | social_handle → employee_id via social_handle_map | + emotion_tags TEXT[], keyword_flags TEXT[] |
| silver_geo_anomalies | social_handle → employee_id via social_handle_map | classified_location_type, anomaly_flag, work_hours_flag, incongruity_flag |
| silver_lifestyle_incongruity | social_handle → employee_id via social_handle_map | signal_type, estimated_value_usd, salary_band, incongruity_score, cumulative_30day_spend |
| silver_financial_stress | direct (employee_id native) | record_type, amount_usd, stress_score, cumulative_stress_score |
| silver_darkweb_signals | email → directory OR social_handle → social_handle_map | signal_type, severity, confidence_score, matched_on |

### OSINT Silver Resolution Patterns

**Twitter (sv_pai UPDATE):** Twitter OSINT does NOT insert new rows. It UPDATEs
existing sv_pai rows (already populated by the internal PAI resolver) to add
`emotion_tags` and `keyword_flags` via ILIKE pattern matching on tweet text.
Uses `skip_truncate=True` in the resolver to prevent clearing sv_pai before
the UPDATE. Emotion patterns: frustration, grievance, disengagement, distress,
hostility. Keyword patterns: sensitive_terms, financial_stress, employment_concern,
job_seeking.

**Dark web (dual-path resolution):** Resolves via two paths ORed together:
`email → directory` OR `social_handle → social_handle_map`. Uses LEFT JOIN on
both, COALESCE for employee_id. `matched_on` column tracks which identifier
resolved the record. Inherently noisy — many signals won't match.

**Lifestyle (salary band join):** Joins `sv_hris` for salary_band derivation.
Incongruity score = `estimated_value_usd / salary_band_baseline` where baselines
are senior=5000, mid=2000, low=1000. Must run AFTER internal Silver completes.

**Resolution thresholds:** Internal domains require ≥90% resolution rate.
OSINT domains require ≥30% (triggered by `domain.startswith("osint_")`).
Below threshold raises RuntimeError and halts the pipeline.

**Asset assignment (shared machines):** Network and DLP use ROW_NUMBER()
partitioned by machine_id, ordered by effective_start DESC NULLS LAST —
most recent assignment wins for identity resolution.

### Gold OSINT Stream Tables

| Table | Grain | Key Score |
|---|---|---|
| gold_twitter_risk | employee + week_start_date | sentiment_risk_score (0-1) |
| gold_location_risk | employee + week_start_date | location_risk_score (0-1) |
| gold_lifestyle_risk | employee + week_start_date | lifestyle_risk_score (0-1) |
| gold_financial_stress_risk | employee + week_start_date | financial_risk_score (0-1) |
| gold_darkweb_risk | employee + week_start_date | darkweb_risk_score (0-1) |
| gold_composite_risk | employee + week_start_date | composite_risk_score (0-1), risk_tier, recommended_action |

### Gold Scoring Formulas

Each OSINT Gold stream produces a 0–1 risk score per employee per week.

**Twitter risk:** Rolling sentiment trend vs 30-day baseline + primary emotion tag.
**Location risk:** `SUM(anomaly_flag) / COUNT(*)` from silver_geo_anomalies.
**Lifestyle risk:** `MAX(incongruity_score)` clamped to [0, 1].
**Financial risk:** `MAX(cumulative_stress_score)` clamped to [0, 1].
**Dark web risk:** `LEAST(1.0, COUNT(*) * 0.15 + MAX(severity_numeric))` where
severity_numeric: high=0.60, medium=0.30, low=0.10.
**Internal behavioral:** `AVG(anomaly_percentile / 100.0)` from employee_risk_features.

### Composite Risk Weights

All stream scores are [0, 1]. Weights sum to 1.0:

```
internal_behavioral = 0.25    # foundational MADlib signal
financial_stress    = 0.18    # strongest motive indicator
twitter_sentiment   = 0.15
lifestyle           = 0.15
dark_web            = 0.15    # risk amplifier + access vector
location            = 0.12    # corroborating, rarely standalone
```

**Risk tiers:** CRITICAL ≥0.75, HIGH ≥0.50, MEDIUM ≥0.25, LOW <0.25.
**Recommended actions:** ESCALATE, INVESTIGATE, MONITOR, ROUTINE.

### Behavioral Realism — Lead/Lag Timeline (90-day window)

Threat actor cohort: 25 employees, deterministic via
`np.random.default_rng(RANDOM_SEED).choice(EMPLOYEE_COUNT, size=25, replace=False)`.
Same seed produces identical cohort in s1_generate_raw and generate_osint_streams.
Each OSINT generator uses a seed offset (+100 twitter, +200 instagram, +300 lifestyle,
+400 financial, +500 darkweb) for independent but reproducible streams.

Tweet sentiment phases for threat actors: days 1–24 benign (0.2–0.9), days 25–50
subtle decline (-0.1–0.2), days 50–65 frustration (-0.4–0.0), days 65+ critical
(-0.9– -0.4). Non-threat employees always positive (0.2–0.9).

| Days | Signal Active |
|---|---|
| 1–20 | Lifestyle incongruity (spending up, luxury purchases) |
| 15–35 | Financial stress public records emerge |
| 25–50 | Twitter sentiment begins declining |
| 40–60 | Instagram sensitive location visits |
| 55–75 | Dark web signals correlate |
| 60–90 | Internal behavioral signals spike |
| 75–90 | Composite risk crosses CRITICAL threshold |

### OSINT Generator

`scripts/generate_osint_streams.py` — standalone, callable from s1 or CLI.
Called automatically from `s1_generate_raw.run()` at end of Bronze generation.
Outputs to `data/bronze/osint/` and uploads to MinIO `bronze/osint/` prefix.

### Airflow DAG Flow (with OSINT)

```
s1_generate (Bronze: 12 internal + 5 OSINT streams)
  └── s2_resolve_domain × 8 (internal Silver, parallel)
        └── s2_collect_internal (fan-in)
              └── s2_resolve_domain × 5 (OSINT Silver, parallel)
                    └── s3_score (internal MADlib + 5 OSINT Gold tables + composite)
                          └── s5_validate
                                └── s6_report
```

---

## Superset Dashboard (`s7_setup_superset.py`)

Creates a three-column catalog dashboard in Apache Superset showing Bronze
sources, Silver domain tables, and Gold risk tables with row counts and
descriptions. Priority-sorted by signal importance.

**Approach:** Superset 3.x rejects complex SQL (subqueries, UNION ALL with
COUNT) in virtual datasets. The script creates **physical catalog tables** in
Greenplum (`dashboard_bronze_catalog`, `dashboard_silver_catalog`,
`dashboard_gold_catalog`) via `CREATE TABLE AS` with the UNION ALL query,
then registers them as physical table datasets in Superset.

**Steps:** Teardown → Register GP database → Create catalog tables in GP →
Register datasets → Create table charts → Create dashboard.

## Airflow DAG Implementation Notes

The DAG uses `expand_kwargs` to parallelize Silver domains. The `upstream_result`
parameter in `s2_resolve_domain` is a dependency hook only — its value is not
used, but passing it forces Airflow to schedule the task after the upstream
completes. `s2_collect_internal` is a fan-in task that waits for all 8 internal
Silver domains before OSINT Silver starts.

---

## Out of Scope (This Phase)

- Generative AI / RAG explanation layer (future Sovereign AI phase)
- Supervised ML or any labeled training sets
- Integration with live external data sources
