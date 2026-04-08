# Sentinel-TDI — Insider Threat Detection Pipeline

A synthetic data pipeline demonstrating the Tanzu Data Intelligence (TDI) stack
for insider threat detection. Medallion architecture (Bronze → Silver → Gold)
orchestrated via Apache Airflow, running on Greenplum 7.x with MADlib anomaly scoring.

**Pipeline narrative:** Classical ML (MADlib k-means) finds the behavioral signal
inside Greenplum — no external model server. The data warehouse is the inference engine.

---

## Architecture

```
Bronze (MinIO / S3)
    Raw synthetic events — 8 source domains, source-native identifiers
    Accessed in Greenplum via PXF external tables

Silver (Greenplum)
    Identity resolution: badge_id / machine_id / email → employee_id
    One table per domain, daily grain, full lineage on every row

Gold (Greenplum + MADlib)
    Cross-domain feature derivation, 7-day rolling windows
    MADlib kmeanspp anomaly scoring — distance from centroid = risk score
```

Airflow TaskFlow DAG runs daily: Bronze → 8 parallel Silver tasks → Gold → Validate → Report.

---

## Prerequisites

- Python 3.11
- Greenplum 7.x with MADlib 2.2+ and PXF 3.0+ installed
- MinIO (or any S3-compatible store) reachable from Greenplum segment hosts
- Apache Airflow 2.9+ (only needed to run the DAG — scripts are also runnable directly)

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/Sentinel-TDI.git
cd Sentinel-TDI
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` with your actual values:

```
GP_HOST=<greenplum-host>
GP_PORT=5432
GP_DB=<database-name>
GP_USER=<user>
GP_PASSWORD=<password>

MINIO_ENDPOINT=http://<minio-host>:9000
MINIO_ACCESS_KEY=<access-key>
MINIO_SECRET_KEY=<secret-key>
MINIO_BUCKET=sentinel-bronze
```

### 4. Configure PXF for MinIO

PXF needs to know how to reach MinIO from the Greenplum hosts.
Copy the template and fill in your MinIO credentials:

```bash
cp config/pxf-minio-server/s3-site.xml.example config/pxf-minio-server/s3-site.xml
```

Edit `s3-site.xml` — set `fs.s3a.endpoint`, `fs.s3a.access.key`, and `fs.s3a.secret.key`.

Then deploy it to the PXF server config directory on your Greenplum host:

```bash
# On the Greenplum host (as gpadmin)
mkdir -p $GPHOME/pxf/servers/minio
cp config/pxf-minio-server/s3-site.xml $GPHOME/pxf/servers/minio/
pxf cluster sync
```

### 5. Apply the Greenplum DDL

Run this once to create all three schemas and tables:

```bash
psql -h $GP_HOST -U $GP_USER -d $GP_DB -f ddl/ddl.sql
```

---

## Running the pipeline

### Option A — Airflow (recommended)

**Link the DAG into your Airflow DAGs folder:**

```bash
ln -s $(pwd)/dags/insider_threat_dag.py ~/airflow/dags/
# or copy it
cp dags/insider_threat_dag.py ~/airflow/dags/
```

**Add the Greenplum connection in Airflow UI:**

Admin → Connections → Add a new record:

| Field | Value |
|---|---|
| Conn ID | `greenplum_default` |
| Conn Type | Postgres |
| Host | your Greenplum host |
| Schema | your database name |
| Login | your GP user |
| Password | your GP password |
| Port | 5432 |

**Set environment variables for the Airflow worker:**

The pipeline scripts read all config from environment variables (same as `.env`).
Add them to your Airflow worker environment or set them in `airflow.cfg` under `[core] > default_env_vars`.

**Trigger the DAG:**

In the Airflow UI, find `insider_threat_pipeline` and click Run.

### Option B — Run scripts directly

Each stage is independently runnable:

```bash
cd scripts

python s1_generate_raw.py        # Generate Bronze synthetic data → uploads to MinIO
python s2_transform_silver.py    # Resolve identities → load Silver tables in GP
python s3_score_gold.py          # Derive features + MADlib scoring → Gold tables
python s5_validate_pipeline.py   # Run validation checks and lineage report
python s6_report_analytics.py    # Generate executive analytics report
```

To run the full pipeline in sequence:

```bash
cd scripts
python s0_orchestrate.py
```

---

## Pipeline stages

| Script | Layer | What it does |
|---|---|---|
| `s1_generate_raw.py` | Bronze | Generates synthetic events for 8 internal domains + 5 OSINT streams (500 employees, 90-day timeline), uploads to MinIO |
| `generate_osint_streams.py` | Bronze | OSINT sub-generator called by s1 — Twitter, Instagram, Lifestyle, Financial Stress, Dark Web |
| `s2_transform_silver.py` | Silver | Resolves source identifiers to `employee_id`, loads 8 internal + 4 OSINT Silver tables in Greenplum |
| `s3_score_gold.py` | Gold | Joins Silver domains, derives behavioral features, runs MADlib kmeanspp; also scores 5 OSINT Gold stream tables + composite |
| `s5_validate_pipeline.py` | QA | Checks coverage, identity resolution rates, null rates, cluster distribution, and OSINT stream table populations |
| `s6_report_analytics.py` | Report | Writes executive analytics and validation reports to `reports/` |
| `s4_build_platform.py` | Platform | Regenerates DDL, DAG, and MADlib SQL from templates (dev use) |

### OSINT Augmentation (5 external behavioral streams)

The pipeline includes 5 OSINT streams that add external behavioral context to the composite risk score. Each follows the same Bronze → Silver → Gold pattern as the internal enterprise data.

| Stream | Bronze Source | Silver Table | Gold Table | Weight |
|---|---|---|---|---|
| Twitter/X sentiment | `raw_tweets.csv` | `sv_pai` (emotion_tags added) | `gold_twitter_risk` | 15% |
| Instagram location | `raw_instagram_posts.csv` | `silver_geo_anomalies` | `gold_location_risk` | 12% |
| Lifestyle signals | `raw_lifestyle_signals.csv` | `silver_lifestyle_incongruity` | `gold_lifestyle_risk` | 15% |
| Financial stress | `raw_financial_stress.csv` | `silver_financial_stress` | `gold_financial_stress_risk` | 18% |
| Dark web signals | `raw_darkweb_signals.csv` | `silver_darkweb_signals` | `gold_darkweb_risk` | 15% |
| Internal behavioral | (8 enterprise domains) | `sv_*` tables | `employee_risk_features` | 25% |

The **composite risk score** (`gold_composite_risk`) fuses all 6 streams into a single weekly score per employee with a risk tier (LOW / MEDIUM / HIGH / CRITICAL) and a recommended action.

---

## MADlib scoring

Gold-layer scoring runs inside Greenplum — no external model server required.

- **Training:** `sql/madlib_train.sql` — k-means++ on normalized 9-feature vectors
- **Scoring:** `sql/madlib_score.sql` — distance from assigned centroid = anomaly score
- **Tiers:** TOP 5% → HIGH, 75th–95th percentile → MEDIUM, below → LOW

---

## Directory structure

```
scripts/         Pipeline scripts (s0–s6) + generate_osint_streams.py
config/          PXF server config templates
dags/            Airflow TaskFlow DAG
data/
  bronze/        Generated CSV/JSON files (gitignored, created at runtime)
    osint/       OSINT Bronze stream files (5 streams)
  silver/        Parquet outputs per domain (gitignored)
  gold/          Parquet risk feature table (gitignored)
ddl/
  ddl.sql        Greenplum DDL — Bronze, Silver, Gold (internal)
  ddl_osint.sql  Greenplum DDL — Bronze, Silver, Gold (OSINT augmentation)
reports/         Generated validation and analytics reports (gitignored)
scdf/            SCDF stream definitions (reference/narrative only)
sql/             MADlib training and scoring SQL
schema/          Generated schema documentation (gitignored)
```

---

## Security note

`config/pxf-minio-server/s3-site.xml` and `.env` are gitignored — they contain
credentials and must never be committed. Only the `.example` templates are in source control.
