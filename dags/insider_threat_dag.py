"""
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
import pendulum

# Make pipeline scripts importable from Airflow worker
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

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
            f"{stage} failed: rows_in={result.get('rows_in')} "
            f"rows_out={result.get('rows_out')} artifacts={result.get('artifacts')}"
        )
    if result.get("rows_out", 0) == 0 and stage not in ("s4_build_platform", "s6_report_analytics"):
        raise AirflowException(f"{stage} produced zero output rows — aborting.")


@dag(
    dag_id="insider_threat_pipeline",
    schedule="@daily",
    start_date=pendulum.now("UTC").subtract(days=1),
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
