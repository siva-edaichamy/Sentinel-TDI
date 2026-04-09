"""
insider_threat_dag.py — Insider Threat Detection Pipeline
Airflow TaskFlow API | Schedule: @daily | Greenplum 7.x + MADlib

Pipeline flow:
    s1_generate_raw (Bronze: 12 internal + 5 OSINT streams)
        └── s2_transform_silver — internal (8 domains in parallel)
                └── s2_collect_internal (fan-in)
                        └── s2_transform_silver — OSINT (5 domains in parallel)
                                └── s3_score_gold (internal MADlib + OSINT Gold stream scoring)
                                        └── s5_validate_pipeline
                                                └── s6_report_analytics

Internal Silver domains run first (parallel). OSINT Silver follows — osint_lifestyle
joins sv_hris so must run after internal Silver completes. Gold runs after all 13 Silver
domains are populated. OSINT Gold stream scoring (5 weekly risk tables + composite) is
handled inside s3_score_gold.run().
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

# 8 internal Silver domains — run in parallel immediately after Bronze
INTERNAL_SILVER_DOMAINS = [
    "hris", "pacs", "network", "dlp",
    "comms", "pai", "geo", "adjudication",
]

# 5 OSINT Silver domains — run in parallel AFTER internal Silver completes
# (osint_lifestyle JOINs sv_hris; others are independent but batched for clarity)
OSINT_SILVER_DOMAINS = [
    "osint_twitter", "osint_instagram", "osint_lifestyle",
    "osint_financial", "osint_darkweb",
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
    start_date=pendulum.datetime(2026, 4, 1, tz="UTC"),
    catchup=False,
    tags=["insider_threat", "tdi", "medallion", "osint"],
    doc_md=__doc__,
)
def insider_threat_pipeline():

    @task()
    def s1_generate():
        result = s1_generate_raw.run(dry_run=False, env=ENV, log_level=LOG_LEVEL)
        _check(result, "s1_generate_raw")
        return result

    @task()
    def s2_resolve_domain(domain: str, upstream_result: dict) -> dict:
        """Resolve a single Silver domain. upstream_result is used only as a dependency hook."""
        result = s2_transform_silver.run_domain(
            domain=domain, dry_run=False, env=ENV, log_level=LOG_LEVEL
        )
        _check(result, f"s2_transform_silver [{domain}]")
        return result

    @task()
    def s2_collect_internal(results: list[dict]) -> dict:
        """Fan-in: collect all internal Silver results into a single dict for downstream dependency."""
        rows_out = sum(r.get("rows_out", 0) for r in results)
        domains  = [r.get("domain", "?") for r in results]
        return {"status": "success", "rows_out": rows_out, "domains": domains}

    @task()
    def s3_score(osint_silver_results: list[dict]) -> dict:
        """Run Gold scoring after all Silver (internal + OSINT) domains complete."""
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

    # --- Execution graph ---

    # Stage 1: Bronze (internal + OSINT)
    bronze = s1_generate()

    # Stage 2a: Internal Silver — 8 domains in parallel
    internal_silver = s2_resolve_domain.expand_kwargs(
        [{"domain": d, "upstream_result": bronze} for d in INTERNAL_SILVER_DOMAINS]
    )

    # Fan-in: wait for all 8 internal Silver domains before OSINT starts
    internal_done = s2_collect_internal(internal_silver)

    # Stage 2b: OSINT Silver — 5 domains in parallel, after internal Silver
    osint_silver = s2_resolve_domain.expand_kwargs(
        [{"domain": d, "upstream_result": internal_done} for d in OSINT_SILVER_DOMAINS]
    )

    # Stage 3: Gold scoring (internal MADlib + OSINT Gold stream tables + composite)
    gold = s3_score(osint_silver)

    # Stage 5 & 6: Validation and reporting
    validation = s5_validate(gold)
    s6_report(validation)


dag_instance = insider_threat_pipeline()
