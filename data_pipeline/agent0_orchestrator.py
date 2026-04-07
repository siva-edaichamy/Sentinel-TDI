"""
agent0_orchestrator.py — Full pipeline orchestration.

Calls each agent's run() directly (not subprocess) in strict dependency order.
Uses the standard return dict to decide whether to proceed or halt.

Execution order:
    agent1_bronze   (no deps)
    agent2_silver   (requires bronze)
    agent3_gold     (requires silver)
    agent4_platform (requires gold — generates platform artifacts)
    agent5_validation (requires gold)
    agent6_analytics  (requires gold + validation)

Writes a pipeline run record to insider_threat_bronze.pipeline_runs after each stage.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

import agent1_bronze
import agent2_silver
import agent3_gold
import agent4_platform
import agent5_validation
import agent6_analytics

from agents.db import get_connection, close_all_pools

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline run audit
# ---------------------------------------------------------------------------

def _log_run(
    env: str,
    run_id: str,
    agent_name: str,
    status: str,
    result: dict,
    dry_run: bool,
) -> None:
    """Write a pipeline_runs record to the Bronze audit table."""
    if dry_run:
        logger.debug("[DRY-RUN] Would log pipeline run for %s", agent_name)
        return
    try:
        with get_connection(env) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO insider_threat_bronze.pipeline_runs
                        (run_id, agent_name, started_at, completed_at, status,
                         rows_in, rows_out, duration_seconds, artifacts, notes)
                    VALUES (%s, %s, NOW(), NOW(), %s, %s, %s, %s, %s, %s)
                """, (
                    run_id,
                    agent_name,
                    status,
                    result.get("rows_in", 0),
                    result.get("rows_out", 0),
                    result.get("duration_seconds", 0),
                    result.get("artifacts", []),
                    json.dumps({k: v for k, v in result.items()
                                if k not in ("artifacts",)}, default=str),
                ))
            conn.commit()
    except Exception as e:
        logger.warning("Failed to log pipeline run for %s: %s", agent_name, e)


# ---------------------------------------------------------------------------
# Stage runner
# ---------------------------------------------------------------------------

def _run_stage(
    agent_module,
    stage_name: str,
    run_id: str,
    dry_run: bool,
    env: str,
    log_level: str,
    halt_on_failure: bool = True,
) -> dict:
    """
    Run a single agent stage, log the result, and optionally halt on failure.
    Returns the agent result dict.
    """
    logger.info("=" * 60)
    logger.info("STAGE START: %s", stage_name)
    logger.info("=" * 60)

    result = agent_module.run(dry_run=dry_run, env=env, log_level=log_level)

    status = result.get("status", "failure")
    rows_out = result.get("rows_out", 0)
    duration = result.get("duration_seconds", 0)

    logger.info(
        "STAGE %s: %s | rows_out=%d duration=%.2fs",
        "DONE" if status == "success" else "FAILED",
        stage_name, rows_out, duration,
    )

    _log_run(env, f"{run_id}_{stage_name}", stage_name, status, result, dry_run)

    if halt_on_failure and status != "success":
        raise RuntimeError(
            f"Stage '{stage_name}' returned status='{status}'. "
            f"rows_in={result.get('rows_in')} rows_out={rows_out}. Halting pipeline."
        )

    if halt_on_failure and rows_out == 0 and stage_name not in ("agent4_platform",):
        raise RuntimeError(
            f"Stage '{stage_name}' produced zero output rows. Halting pipeline."
        )

    return result


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(dry_run: bool = False, env: str = "local", log_level: str = "INFO") -> dict:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    t0 = time.perf_counter()
    pipeline_run_id = str(uuid.uuid4())

    logger.info("=" * 60)
    logger.info("PIPELINE START | run_id=%s dry_run=%s env=%s", pipeline_run_id, dry_run, env)
    logger.info("=" * 60)

    stage_results: dict[str, dict] = {}
    all_artifacts: list[str] = []
    failed_stage: str | None = None

    stages = [
        (agent1_bronze,    "agent1_bronze"),
        (agent2_silver,    "agent2_silver"),
        (agent3_gold,      "agent3_gold"),
        (agent4_platform,  "agent4_platform"),
        (agent5_validation,"agent5_validation"),
        (agent6_analytics, "agent6_analytics"),
    ]

    try:
        for agent_module, stage_name in stages:
            result = _run_stage(
                agent_module, stage_name, pipeline_run_id,
                dry_run=dry_run, env=env, log_level=log_level,
            )
            stage_results[stage_name] = result
            all_artifacts.extend(result.get("artifacts", []))

    except RuntimeError as exc:
        failed_stage = str(exc)
        logger.error("PIPELINE HALTED: %s", failed_stage)
    except Exception as exc:
        failed_stage = str(exc)
        logger.exception("PIPELINE UNEXPECTED FAILURE: %s", exc)
    finally:
        close_all_pools()

    duration = time.perf_counter() - t0
    status = "success" if failed_stage is None else "failure"

    # Pipeline-level summary
    logger.info("=" * 60)
    logger.info(
        "PIPELINE %s | run_id=%s | duration=%.2fs | stages=%d/%d",
        status.upper(), pipeline_run_id, duration,
        sum(1 for r in stage_results.values() if r.get("status") == "success"),
        len(stages),
    )
    logger.info("=" * 60)

    # Stage summary table
    for name, result in stage_results.items():
        logger.info(
            "  %-22s status=%-8s rows_in=%-8s rows_out=%-8s duration=%.2fs",
            name,
            result.get("status", "?"),
            result.get("rows_in", "?"),
            result.get("rows_out", "?"),
            result.get("duration_seconds", 0),
        )

    total_rows_in  = sum(r.get("rows_in", 0)  for r in stage_results.values())
    total_rows_out = sum(r.get("rows_out", 0) for r in stage_results.values())

    return {
        "status": status,
        "rows_in": total_rows_in,
        "rows_out": total_rows_out,
        "duration_seconds": round(duration, 3),
        "artifacts": all_artifacts,
        "pipeline_run_id": pipeline_run_id,
        "stages": {name: r.get("status") for name, r in stage_results.items()},
        "failed_stage": failed_stage,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="agent0_orchestrator — full pipeline run")
    p.add_argument("--dry-run",   action="store_true",
                   help="Pass --dry-run to all agents (no file or DB writes)")
    p.add_argument("--env",       default="local", choices=["local", "dev", "prod"])
    p.add_argument("--log-level", default="INFO",  choices=["DEBUG", "INFO", "WARNING"])
    p.add_argument("--from-stage", default=None,
                   choices=["agent2_silver", "agent3_gold", "agent4_platform",
                            "agent5_validation", "agent6_analytics"],
                   help="Skip stages before this one (resume from mid-pipeline)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.from_stage:
        # Resume from a specific stage — skip earlier ones
        skip = {"agent2_silver": 1, "agent3_gold": 2, "agent4_platform": 3,
                "agent5_validation": 4, "agent6_analytics": 5}
        skip_count = skip.get(args.from_stage, 0)

        # Monkey-patch run() to skip the first N stages
        _original_run = run
        _skip = skip_count
        def _partial_run(dry_run, env, log_level):
            import importlib
            all_stages = [
                (agent1_bronze,    "agent1_bronze"),
                (agent2_silver,    "agent2_silver"),
                (agent3_gold,      "agent3_gold"),
                (agent4_platform,  "agent4_platform"),
                (agent5_validation,"agent5_validation"),
                (agent6_analytics, "agent6_analytics"),
            ]
            logging.basicConfig(
                level=getattr(logging, log_level.upper(), logging.INFO),
                format="%(asctime)s %(name)s %(levelname)s %(message)s",
            )
            t0 = time.perf_counter()
            run_id = str(uuid.uuid4())
            logger.info("PIPELINE RESUME from %s | run_id=%s", args.from_stage, run_id)
            stage_results = {}
            artifacts = []
            try:
                for agent_module, stage_name in all_stages[_skip:]:
                    result = _run_stage(agent_module, stage_name, run_id,
                                        dry_run=dry_run, env=env, log_level=log_level)
                    stage_results[stage_name] = result
                    artifacts.extend(result.get("artifacts", []))
            finally:
                close_all_pools()
            return {
                "status": "success" if all(r.get("status") == "success" for r in stage_results.values()) else "failure",
                "rows_in": sum(r.get("rows_in", 0) for r in stage_results.values()),
                "rows_out": sum(r.get("rows_out", 0) for r in stage_results.values()),
                "duration_seconds": round(time.perf_counter() - t0, 3),
                "artifacts": artifacts,
                "pipeline_run_id": run_id,
                "stages": {n: r.get("status") for n, r in stage_results.items()},
            }
        result = _partial_run(args.dry_run, args.env, args.log_level)
    else:
        result = run(dry_run=args.dry_run, env=args.env, log_level=args.log_level)

    print(json.dumps(result, indent=2, default=str))
