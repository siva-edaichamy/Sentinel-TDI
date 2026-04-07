"""
s4_build_platform.py — Platform artifact generation.

Generates:
  1. dags/insider_threat_dag.py     — Airflow TaskFlow DAG (runnable)
  2. scdf/stream_definitions.txt    — SCDF DSL reference (narrative)
  3. sql/madlib_train.sql           — MADlib k-means training SQL (final form)
  4. sql/madlib_score.sql           — Anomaly scoring SQL (final form)
  5. manifest.yml                   — Cloud Foundry TAS deployment manifest

This agent writes/overwrites these artifacts. It does NOT execute them.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

PIPELINE_VERSION = os.getenv("PIPELINE_VERSION", "s4_build_platform_v1")
AIRFLOW_DAG_OWNER = os.getenv("AIRFLOW_DAG_OWNER", "airflow")
GOLD_SCHEMA = "insider_threat_gold"
KMEANS_K = 5
KMEANS_MAX_ITER = 20
KMEANS_TOLERANCE = 0.001

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Airflow DAG
# ---------------------------------------------------------------------------

def _gen_airflow_dag() -> str:
    return '''"""
insider_threat_dag.py — Insider Threat Detection Pipeline
Airflow TaskFlow API | Schedule: @daily | Greenplum 7.x + MADlib

Pipeline flow:
    s1_generate_raw
        └── s2_transform_silver (8 domains in parallel)
                └── s3_score_gold
                        └── s5_validate_pipeline
                                └── s6_report_analytics

Each Silver domain runs as an independent parallel task — identity resolution
is pure SQL inside Greenplum against ext_* PXF external tables on MinIO.
"""

from __future__ import annotations

import sys
from pathlib import Path

from airflow.decorators import dag, task
from airflow.exceptions import AirflowException
from airflow.utils.dates import days_ago

# Make pipeline scripts importable from Airflow worker
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import s1_generate_raw
import s2_transform_silver
import s3_score_gold
import s5_validate_pipeline
import s6_report_analytics

ENV       = "prod"
LOG_LEVEL = "INFO"

SILVER_DOMAINS = [
    "hris", "pacs", "network", "dlp",
    "comms", "pai", "geo", "adjudication",
]


def _check(result: dict, stage: str) -> None:
    """Raise AirflowException if a stage returned failure or zero rows."""
    if result.get("status") != "success":
        raise AirflowException(
            f"{stage} failed: rows_in={result.get(\'rows_in\')} "
            f"rows_out={result.get(\'rows_out\')} artifacts={result.get(\'artifacts\')}"
        )
    if result.get("rows_out", 0) == 0 and stage not in ("s4_build_platform", "s6_report_analytics"):
        raise AirflowException(f"{stage} produced zero output rows — aborting.")


@dag(
    dag_id="insider_threat_pipeline",
    schedule_interval="@daily",
    start_date=days_ago(1),
    catchup=False,
    tags=["insider_threat", "tdi", "medallion"],
    doc_md=__doc__,
)
def insider_threat_pipeline():

    @task()
    def s1_generate():
        result = s1_generate_raw.run(dry_run=False, env=ENV, log_level=LOG_LEVEL)
        _check(result, "s1_generate_raw")
        return result

    @task()
    def s2_resolve_domain(domain: str, bronze_result: dict) -> dict:
        result = s2_transform_silver.run_domain(
            domain=domain, dry_run=False, env=ENV, log_level=LOG_LEVEL
        )
        _check(result, f"s2_transform_silver [{domain}]")
        return result

    @task()
    def s3_score(silver_results: list[dict]) -> dict:
        result = s3_score_gold.run(dry_run=False, env=ENV, log_level=LOG_LEVEL)
        _check(result, "s3_score_gold")
        return result

    @task()
    def s5_validate(gold_result: dict) -> dict:
        result = s5_validate_pipeline.run(dry_run=False, env=ENV, log_level=LOG_LEVEL)
        _check(result, "s5_validate_pipeline")
        return result

    @task()
    def s6_report(validation_result: dict) -> dict:
        result = s6_report_analytics.run(dry_run=False, env=ENV, log_level=LOG_LEVEL)
        _check(result, "s6_report_analytics")
        return result

    bronze = s1_generate()

    silver_results = s2_resolve_domain.expand_kwargs(
        [{"domain": d, "bronze_result": bronze} for d in SILVER_DOMAINS]
    )

    gold       = s3_score(silver_results)
    validation = s5_validate(gold)
    s6_report(validation)


dag_instance = insider_threat_pipeline()
'''


# ---------------------------------------------------------------------------
# SCDF stream definitions
# ---------------------------------------------------------------------------

def _gen_scdf() -> str:
    return """# SCDF Stream Definitions — Insider Threat Real-Time Silver Streams
# Reference/narrative artifact only — not runnable in this phase.
# Airflow handles batch orchestration; SCDF handles real-time event streaming
# from RabbitMQ into Silver. Both write to the same Greenplum tables.

# PACS badge swipe — real-time Silver stream
pacs-silver = rabbit --queues=pacs.raw \\
  | badge-resolver --mapping-table=insider_threat_bronze.badge_registry \\
  | jdbc --url=${GP_JDBC_URL} --table-name=insider_threat_silver.sv_pacs

# Network log — real-time Silver stream
network-silver = rabbit --queues=network.raw \\
  | asset-resolver --mapping-table=insider_threat_bronze.asset_assignment \\
  | jdbc --url=${GP_JDBC_URL} --table-name=insider_threat_silver.sv_network

# DLP events — real-time Silver stream
dlp-silver = rabbit --queues=dlp.raw \\
  | asset-resolver --mapping-table=insider_threat_bronze.asset_assignment \\
  | jdbc --url=${GP_JDBC_URL} --table-name=insider_threat_silver.sv_dlp

# Comms metadata — real-time Silver stream
comms-silver = rabbit --queues=comms.raw \\
  | directory-resolver --mapping-table=insider_threat_bronze.directory \\
  | jdbc --url=${GP_JDBC_URL} --table-name=insider_threat_silver.sv_comms

# PAI sentiment — real-time Silver stream
pai-silver = rabbit --queues=pai.raw \\
  | social-resolver --mapping-table=insider_threat_bronze.social_handle_map \\
  | jdbc --url=${GP_JDBC_URL} --table-name=insider_threat_silver.sv_pai

# Geo events — real-time Silver stream
geo-silver = rabbit --queues=geo.raw \\
  | badge-resolver --mapping-table=insider_threat_bronze.badge_registry \\
  | jdbc --url=${GP_JDBC_URL} --table-name=insider_threat_silver.sv_geo
"""


# ---------------------------------------------------------------------------
# MADlib SQL (final/canonical form)
# ---------------------------------------------------------------------------

def _gen_madlib_train() -> str:
    return f"""-- madlib_train.sql — MADlib k-means training (canonical)
-- MADlib 2.2.0: kmeanspp() returns a result row — store via CREATE TABLE AS
-- Prerequisite: GRANT USAGE ON SCHEMA madlib TO gpadmin;
--               GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA madlib TO gpadmin;

-- Drop prior model output
DROP TABLE IF EXISTS {GOLD_SCHEMA}.gd_kmeans_output;

-- Train k-means++ on normalized feature vectors
-- k={KMEANS_K} clusters, squared L2 distance, up to {KMEANS_MAX_ITER} iterations
-- WITH clause must appear before AS; DISTRIBUTED clause after the query in GP
CREATE TABLE {GOLD_SCHEMA}.gd_kmeans_output
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
AS
SELECT * FROM madlib.kmeanspp(
    '{GOLD_SCHEMA}.employee_features',   -- source table
    'feature_vector',                    -- feature column (FLOAT8[])
    {KMEANS_K},                          -- k
    'madlib.squared_dist_norm2',         -- distance function
    'madlib.avg',                        -- centroid update function
    {KMEANS_MAX_ITER},                   -- max iterations
    {KMEANS_TOLERANCE}::float8           -- convergence tolerance
)
DISTRIBUTED RANDOMLY;

-- Verify: one row with centroids array, num_iterations, objective_fn
SELECT num_iterations, frac_reassigned, objective_fn FROM {GOLD_SCHEMA}.gd_kmeans_output;
"""


def _gen_madlib_score() -> str:
    return f"""-- madlib_score.sql — Anomaly scoring and percentile ranking (canonical)
-- Reads centroids from gd_kmeans_output produced by madlib_train.sql

-- Drop prior scored output
DROP TABLE IF EXISTS {GOLD_SCHEMA}.gd_scored;

-- Assign each employee-window to nearest centroid, compute distance
-- WITH clause must appear before AS in GP CREATE TABLE AS
CREATE TABLE {GOLD_SCHEMA}.gd_scored
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
AS
SELECT
    ef.employee_id,
    ef.window_end_date,
    (madlib.closest_column(
        km.centroids,
        ef.feature_vector,
        'madlib.squared_dist_norm2'
    )).column_id  AS cluster_id,
    sqrt(
        (madlib.closest_column(
            km.centroids,
            ef.feature_vector,
            'madlib.squared_dist_norm2'
        )).distance
    )             AS anomaly_score
FROM {GOLD_SCHEMA}.employee_features ef
CROSS JOIN {GOLD_SCHEMA}.gd_kmeans_output km
DISTRIBUTED BY (employee_id);

-- Percentile rank
SELECT
    employee_id,
    window_end_date,
    cluster_id,
    anomaly_score,
    PERCENT_RANK() OVER (ORDER BY anomaly_score) * 100 AS anomaly_percentile,
    CASE
        WHEN PERCENT_RANK() OVER (ORDER BY anomaly_score) >= 0.95 THEN 'HIGH'
        WHEN PERCENT_RANK() OVER (ORDER BY anomaly_score) >= 0.75 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS anomaly_tier
FROM {GOLD_SCHEMA}.gd_scored
ORDER BY anomaly_score DESC
LIMIT 20;
"""


# ---------------------------------------------------------------------------
# Analytics SQL
# ---------------------------------------------------------------------------

def _gen_analytics_queries() -> str:
    return f"""-- analytics_queries.sql — Agent 6 dashboard and executive report queries

-- 1. Top 25 highest-risk employees (latest window)
SELECT
    e.employee_id,
    h.full_name,
    h.department,
    h.role_title,
    h.clearance_level,
    e.anomaly_score,
    e.anomaly_percentile,
    e.anomaly_tier,
    e.cross_domain_anomaly_count,
    e.window_end_date
FROM {GOLD_SCHEMA}.employee_risk_features e
JOIN insider_threat_silver.sv_hris h USING (employee_id)
WHERE e.window_end_date = (SELECT MAX(window_end_date) FROM {GOLD_SCHEMA}.employee_risk_features)
  AND e.anomaly_tier = 'HIGH'
ORDER BY e.anomaly_score DESC
LIMIT 25;

-- 2. Risk trend over time for HIGH-tier employees
SELECT
    employee_id,
    window_end_date,
    anomaly_score,
    anomaly_tier,
    cross_domain_anomaly_count
FROM {GOLD_SCHEMA}.employee_risk_features
WHERE employee_id IN (
    SELECT employee_id
    FROM {GOLD_SCHEMA}.employee_risk_features
    WHERE anomaly_tier = 'HIGH'
    GROUP BY employee_id
    HAVING COUNT(*) >= 3
)
ORDER BY employee_id, window_end_date;

-- 3. Cluster population summary
SELECT
    cluster_id,
    COUNT(DISTINCT employee_id) AS employees,
    COUNT(*) AS windows,
    ROUND(AVG(anomaly_score)::numeric, 4) AS avg_score,
    ROUND(MAX(anomaly_score)::numeric, 4) AS max_score,
    ROUND(AVG(cross_domain_anomaly_count)::numeric, 2) AS avg_domains_flagged
FROM {GOLD_SCHEMA}.employee_risk_features
GROUP BY cluster_id
ORDER BY avg_score DESC;

-- 4. Domain signal contribution (which features drive HIGH tier)
SELECT
    anomaly_tier,
    ROUND(AVG(badge_swipes_outlier)::numeric, 3)        AS avg_badge_outlier,
    ROUND(AVG(after_hours_pacs_score)::numeric, 3)      AS avg_ah_pacs,
    ROUND(AVG(after_hours_network_score)::numeric, 3)   AS avg_ah_network,
    ROUND(AVG(usb_exfiltration_score)::numeric, 3)      AS avg_usb_score,
    ROUND(AVG(file_movement_outlier)::numeric, 3)       AS avg_file_movement,
    ROUND(AVG(vpn_anomaly_score)::numeric, 3)           AS avg_vpn_score,
    ROUND(AVG(comms_volume_delta)::numeric, 3)          AS avg_comms_delta,
    ROUND(AVG(sentiment_trend)::numeric, 3)             AS avg_sentiment_trend,
    SUM(CASE WHEN impossible_travel_flag THEN 1 ELSE 0 END) AS impossible_travel_count,
    SUM(CASE WHEN clearance_anomaly_flag THEN 1 ELSE 0 END) AS clearance_anomaly_count
FROM {GOLD_SCHEMA}.employee_risk_features
GROUP BY anomaly_tier
ORDER BY anomaly_tier;

-- 5. Identity resolution audit
SELECT
    source_domain,
    identity_resolution_status,
    COUNT(*) AS record_count
FROM (
    SELECT 'pacs'         AS source_domain, identity_resolution_status FROM insider_threat_silver.sv_pacs
    UNION ALL
    SELECT 'network',     identity_resolution_status FROM insider_threat_silver.sv_network
    UNION ALL
    SELECT 'dlp',         identity_resolution_status FROM insider_threat_silver.sv_dlp
    UNION ALL
    SELECT 'comms',       identity_resolution_status FROM insider_threat_silver.sv_comms
    UNION ALL
    SELECT 'pai',         identity_resolution_status FROM insider_threat_silver.sv_pai
    UNION ALL
    SELECT 'geo',         identity_resolution_status FROM insider_threat_silver.sv_geo
    UNION ALL
    SELECT 'adjudication',identity_resolution_status FROM insider_threat_silver.sv_adjudication
) domains
GROUP BY source_domain, identity_resolution_status
ORDER BY source_domain, identity_resolution_status;

-- 6. Pipeline lineage audit
SELECT run_id, agent_name, status, rows_in, rows_out, duration_seconds, started_at
FROM insider_threat_bronze.pipeline_runs
ORDER BY started_at DESC
LIMIT 20;
"""


# ---------------------------------------------------------------------------
# Cloud Foundry manifest
# ---------------------------------------------------------------------------

def _gen_manifest() -> str:
    gp_host = os.getenv("GP_HOST", "localhost")
    gp_port = os.getenv("GP_PORT", "5432")
    gp_db   = os.getenv("GP_DB", "gpadmin")
    gp_user = os.getenv("GP_USER", "gpadmin")

    return f"""# manifest.yml — Cloud Foundry TAS deployment manifest
# Insider Threat Synthetic Data Pipeline

applications:
  - name: insider-threat-pipeline
    memory: 2G
    disk_quota: 4G
    instances: 1
    buildpacks:
      - python_buildpack
    command: python agents/s0_orchestrate.py --env prod --log-level INFO
    env:
      RANDOM_SEED: "42"
      EMPLOYEE_COUNT: "500"
      TIMELINE_DAYS: "90"
      TIMELINE_START_DATE: "2026-01-01"
      ROLLING_WINDOW: "7"
      GP_HOST: "{gp_host}"
      GP_PORT: "{gp_port}"
      GP_DB: "{gp_db}"
      GP_USER: "{gp_user}"
      # GP_PASSWORD: bind via CF user-provided service or CredHub
      AIRFLOW_DAG_OWNER: airflow
    services:
      - greenplum-insider-threat   # CF service instance binding GP credentials

  - name: insider-threat-airflow
    memory: 1G
    disk_quota: 2G
    instances: 1
    buildpacks:
      - python_buildpack
    command: airflow webserver
    env:
      AIRFLOW__CORE__DAGS_FOLDER: /home/vcap/app/dags
      AIRFLOW__CORE__EXECUTOR: LocalExecutor
"""


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(dry_run: bool = False, env: str = "local", log_level: str = "INFO") -> dict:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    t0 = time.perf_counter()
    logger.info("s4_build_platform START | dry_run=%s env=%s", dry_run, env)

    artifacts: list[str] = []

    def _write(path: Path, content: str) -> str:
        if dry_run:
            logger.info("[DRY-RUN] Would write %s (%d chars)", path, len(content))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            logger.info("Wrote %s", path)
        return str(path)

    try:
        artifacts.append(_write(_PROJECT_ROOT / "dags" / "insider_threat_dag.py",   _gen_airflow_dag()))
        artifacts.append(_write(_PROJECT_ROOT / "scdf" / "stream_definitions.txt",   _gen_scdf()))
        artifacts.append(_write(_PROJECT_ROOT / "sql"  / "madlib_train.sql",          _gen_madlib_train()))
        artifacts.append(_write(_PROJECT_ROOT / "sql"  / "madlib_score.sql",          _gen_madlib_score()))
        artifacts.append(_write(_PROJECT_ROOT / "sql"  / "analytics_queries.sql",     _gen_analytics_queries()))
        artifacts.append(_write(_PROJECT_ROOT / "manifest.yml",                        _gen_manifest()))

        duration = time.perf_counter() - t0
        logger.info("s4_build_platform DONE | artifacts=%d duration=%.2fs", len(artifacts), duration)

        return {
            "status": "success",
            "rows_in": 0,
            "rows_out": len(artifacts),
            "duration_seconds": round(duration, 3),
            "artifacts": artifacts,
        }

    except Exception as exc:
        duration = time.perf_counter() - t0
        logger.exception("agent4_platform FAILED: %s", exc)
        return {
            "status": "failure",
            "rows_in": 0,
            "rows_out": 0,
            "duration_seconds": round(duration, 3),
            "artifacts": artifacts,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="s4_build_platform — platform artifact generation")
    p.add_argument("--dry-run",   action="store_true")
    p.add_argument("--env",       default="local", choices=["local", "dev", "prod"])
    p.add_argument("--log-level", default="INFO",  choices=["DEBUG", "INFO", "WARNING"])
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    result = run(dry_run=args.dry_run, env=args.env, log_level=args.log_level)
    print(json.dumps(result, indent=2))
