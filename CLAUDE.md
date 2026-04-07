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
| RabbitMQ        | Referenced as streaming ingest path (narrative only)         |
| SCDF            | DSL stream definitions included as reference artifacts       |
| Cloud Foundry   | Deployment target (TAS) — `manifest.yml` per app             |
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
| `social_handle_map.csv` | CSV | `social_handle → employee_id` — include ~5% unmapped handles for realism |

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
platform, sentiment_score, post_count, engagement_count
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
**API:** TaskFlow API (`@task` decorators)
**Schedule:** `@daily` — processes prior day's Bronze events

```
bronze_generate
      │
      ├── silver_resolve_pacs
      ├── silver_resolve_network
      ├── silver_resolve_dlp
      ├── silver_resolve_comms
      ├── silver_resolve_pai
      ├── silver_resolve_geo
      ├── silver_resolve_adjudication
      └── silver_resolve_hris
            │
            └── gold_derive_features
                      │
                      └── gold_madlib_train_score
                                │
                                └── gold_validate
                                          │
                                          └── analytics_refresh
```

Silver resolution tasks run in parallel after Bronze completes.
Gold tasks are strictly sequential — features before scoring.

Each task must:
- Log input row count on entry, output row count on exit
- Write a lineage record to `insider_threat_bronze.pipeline_runs`
- Raise `AirflowException` if identity resolution rate falls below 90%
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
(START ('2024-01-01') END ('2025-01-01') EVERY (INTERVAL '1 month'))
```

All timestamp columns: `TIMESTAMP WITH TIME ZONE`

Schema layout:
```
insider_threat_bronze   -- mapping tables + pipeline_runs audit table
insider_threat_silver   -- sv_* domain tables + sv_unresolved_events
insider_threat_gold     -- employee_risk_features + employee_features (MADlib input)
```

---

## SCDF Reference Artifacts

SCDF stream definitions show how Silver transformations would run as real-time
event streams in a production deployment alongside Airflow batch processing.
These are reference/narrative artifacts — Airflow is the runnable layer.

**File:** `scdf/stream_definitions.txt`

```
# PACS badge swipe — real-time Silver stream
pacs-silver = rabbit --queues=pacs.raw \
  | badge-resolver --mapping-table=insider_threat_bronze.badge_registry \
  | jdbc --url=${GP_JDBC_URL} --table-name=insider_threat_silver.sv_pacs

# Network log — real-time Silver stream
network-silver = rabbit --queues=network.raw \
  | asset-resolver --mapping-table=insider_threat_bronze.asset_assignment \
  | jdbc --url=${GP_JDBC_URL} --table-name=insider_threat_silver.sv_network
```

Narrative framing: "Airflow handles scheduled batch ingestion and Gold-layer ML.
SCDF handles real-time event streaming from RabbitMQ into Silver. Both write to
the same Greenplum tables — the warehouse is the integration point."

---

## File and Directory Structure

```
insider_threat_demo/
├── CLAUDE.md
├── manifest.yml                        # Cloud Foundry TAS deployment manifest
├── requirements.txt                    # Python dependencies
├── .env.example                        # Environment variable template
│
├── agents/
│   ├── agent0_orchestrator.py          # Coordinates full pipeline run
│   ├── agent1_bronze.py                # Synthetic data generation (all 8 domains)
│   ├── agent2_silver.py                # Identity resolution + conformance
│   ├── agent3_gold.py                  # Feature derivation + MADlib scoring
│   ├── agent4_platform.py              # DDL + DAG + manifest generation
│   ├── agent5_validation.py            # Pipeline QA and lineage checks
│   └── agent6_analytics.py            # Executive analytics and case narratives
│
├── data/
│   ├── bronze/                         # Raw synthetic files (CSV, JSON)
│   ├── silver/                         # Parquet outputs per domain
│   └── gold/                           # Parquet risk feature table
│
├── ddl/
│   └── ddl.sql                         # All Greenplum DDL — Bronze + Silver + Gold schemas
│
├── dags/
│   └── insider_threat_dag.py           # Airflow TaskFlow DAG (runnable)
│
├── scdf/
│   └── stream_definitions.txt          # SCDF DSL reference (narrative)
│
├── sql/
│   ├── madlib_train.sql                # MADlib k-means training
│   ├── madlib_score.sql                # Anomaly scoring and percentile ranking
│   └── analytics_queries.sql          # Agent 6 dashboard queries
│
├── schema/
│   ├── bronze_schema_map.json
│   ├── silver_lineage_map.json
│   └── feature_dictionary.json
│
└── reports/
    ├── validation_report.md
    └── executive_analytics.md
```

---

## Agent Execution Order

```
agent0_orchestrator
  └─► agent1_bronze          -- verify row counts + schema before proceeding
        └─► agent2_silver    -- verify identity resolution rate + lineage before proceeding
              └─► agent3_gold
                    └─► agent4_platform
                          └─► agent5_validation
                                └─► agent6_analytics
```

Each agent must be independently runnable:
```bash
python agents/agent1_bronze.py
python agents/agent2_silver.py
python agents/agent3_gold.py
# etc.
```

---

## Validation Targets (Agent 5)

| Check | Target |
|---|---|
| Employee coverage in Gold | All 500 EMP IDs present |
| Silver identity resolution rate | ≥ 90% per domain |
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
RANDOM_SEED    = int(os.getenv("RANDOM_SEED", 42))
EMPLOYEE_COUNT = int(os.getenv("EMPLOYEE_COUNT", 500))
TIMELINE_DAYS  = int(os.getenv("TIMELINE_DAYS", 90))
GP_HOST        = os.getenv("GP_HOST", "localhost")
GP_PORT        = int(os.getenv("GP_PORT", 5432))
GP_DB          = os.getenv("GP_DB", "gpadmin")
GP_USER        = os.getenv("GP_USER", "gpadmin")
GP_PASSWORD    = os.getenv("GP_PASSWORD", "")
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

## Out of Scope (This Phase)

- Generative AI / RAG explanation layer (future Sovereign AI phase)
- Runnable SCDF streaming pipelines (reference artifacts only this phase)
- Frontend dashboard
- Supervised ML or any labeled training sets
- Integration with live external data sources
