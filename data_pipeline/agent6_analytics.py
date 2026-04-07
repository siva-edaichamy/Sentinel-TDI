"""
agent6_analytics.py — Executive analytics and case narratives.

Queries the Gold layer to produce:
  1. Executive summary (top risks, cluster profile, domain signal breakdown)
  2. Individual case narratives for HIGH-tier employees
  3. reports/executive_analytics.md

This is the "explain it to the analyst" layer — the output of the
classical ML pipeline expressed in human-readable prose.
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
from typing import Any

import pandas as pd
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.db import get_connection

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

GOLD_SCHEMA   = "insider_threat_gold"
SILVER_SCHEMA = "insider_threat_silver"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data queries
# ---------------------------------------------------------------------------

def _q(env: str, sql: str) -> pd.DataFrame:
    with get_connection(env) as conn:
        return pd.read_sql(sql, conn)


def _fetch_top_risks(env: str, n: int = 25) -> pd.DataFrame:
    return _q(env, f"""
        SELECT
            e.employee_id,
            h.full_name,
            h.department,
            h.role_title,
            h.clearance_level,
            e.anomaly_score,
            e.anomaly_percentile,
            e.anomaly_tier,
            e.cluster_id,
            e.cross_domain_anomaly_count,
            e.badge_swipes_outlier,
            e.after_hours_pacs_score,
            e.after_hours_network_score,
            e.usb_exfiltration_score,
            e.file_movement_outlier,
            e.vpn_anomaly_score,
            e.comms_volume_delta,
            e.sentiment_trend,
            e.impossible_travel_flag,
            e.clearance_anomaly_flag,
            e.window_end_date,
            e.model_run_id
        FROM {GOLD_SCHEMA}.employee_risk_features e
        JOIN {SILVER_SCHEMA}.sv_hris h USING (employee_id)
        WHERE e.window_end_date = (
            SELECT MAX(window_end_date) FROM {GOLD_SCHEMA}.employee_risk_features
        )
          AND e.anomaly_tier = 'HIGH'
        ORDER BY e.anomaly_score DESC
        LIMIT {n}
    """)


def _fetch_cluster_summary(env: str) -> pd.DataFrame:
    return _q(env, f"""
        SELECT
            cluster_id,
            COUNT(DISTINCT employee_id)                         AS employees,
            COUNT(*)                                            AS windows,
            ROUND(AVG(anomaly_score)::numeric, 4)               AS avg_score,
            ROUND(MAX(anomaly_score)::numeric, 4)               AS max_score,
            ROUND(AVG(cross_domain_anomaly_count)::numeric, 2)  AS avg_domains_flagged,
            SUM(CASE WHEN anomaly_tier = 'HIGH'   THEN 1 ELSE 0 END) AS high_windows,
            SUM(CASE WHEN anomaly_tier = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_windows
        FROM {GOLD_SCHEMA}.employee_risk_features
        GROUP BY cluster_id
        ORDER BY avg_score DESC
    """)


def _fetch_tier_signal(env: str) -> pd.DataFrame:
    return _q(env, f"""
        SELECT
            anomaly_tier,
            COUNT(*)                                                AS windows,
            ROUND(AVG(badge_swipes_outlier)::numeric, 3)           AS avg_badge_outlier,
            ROUND(AVG(after_hours_pacs_score)::numeric, 3)         AS avg_ah_pacs,
            ROUND(AVG(after_hours_network_score)::numeric, 3)      AS avg_ah_network,
            ROUND(AVG(usb_exfiltration_score)::numeric, 3)         AS avg_usb_score,
            ROUND(AVG(file_movement_outlier)::numeric, 3)          AS avg_file_movement,
            ROUND(AVG(vpn_anomaly_score)::numeric, 3)              AS avg_vpn_score,
            ROUND(AVG(comms_volume_delta)::numeric, 3)             AS avg_comms_delta,
            ROUND(AVG(sentiment_trend)::numeric, 3)                AS avg_sentiment_trend,
            SUM(CASE WHEN impossible_travel_flag THEN 1 ELSE 0 END) AS impossible_travel,
            SUM(CASE WHEN clearance_anomaly_flag THEN 1 ELSE 0 END) AS clearance_anomaly
        FROM {GOLD_SCHEMA}.employee_risk_features
        GROUP BY anomaly_tier
        ORDER BY anomaly_tier DESC
    """)


def _fetch_risk_trend(env: str, employee_ids: list[str]) -> pd.DataFrame:
    id_list = ", ".join(f"'{e}'" for e in employee_ids[:10])
    return _q(env, f"""
        SELECT
            employee_id, window_end_date, anomaly_score, anomaly_tier,
            cross_domain_anomaly_count
        FROM {GOLD_SCHEMA}.employee_risk_features
        WHERE employee_id IN ({id_list})
        ORDER BY employee_id, window_end_date
    """)


def _fetch_pipeline_stats(env: str) -> dict:
    with get_connection(env) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {GOLD_SCHEMA}.employee_risk_features")
            gold_rows = cur.fetchone()[0]
            cur.execute(f"SELECT COUNT(DISTINCT employee_id) FROM {GOLD_SCHEMA}.employee_risk_features")
            employees = cur.fetchone()[0]
            cur.execute(f"SELECT COUNT(DISTINCT window_end_date) FROM {GOLD_SCHEMA}.employee_risk_features")
            windows = cur.fetchone()[0]
            cur.execute(f"SELECT model_run_id, scored_at FROM {GOLD_SCHEMA}.employee_risk_features LIMIT 1")
            row = cur.fetchone()
    return {
        "gold_rows": gold_rows, "employees": employees,
        "windows": windows, "model_run_id": row[0] if row else None,
        "scored_at": str(row[1]) if row else None,
    }


# ---------------------------------------------------------------------------
# Narrative builders
# ---------------------------------------------------------------------------

def _signal_summary(row: pd.Series) -> str:
    """Build a plain-English signal description for one employee-window."""
    signals = []
    if abs(float(row.get("badge_swipes_outlier", 0) or 0)) > 1.5:
        signals.append("unusual physical access frequency")
    if float(row.get("after_hours_pacs_score", 0) or 0) > 0.2:
        signals.append("elevated after-hours badge activity")
    if float(row.get("after_hours_network_score", 0) or 0) > 0.2:
        signals.append("elevated after-hours network sessions")
    if float(row.get("usb_exfiltration_score", 0) or 0) > 1.5:
        signals.append("anomalous USB write volume")
    if float(row.get("file_movement_outlier", 0) or 0) > 1.5:
        signals.append("unusual file movement activity")
    if float(row.get("vpn_anomaly_score", 0) or 0) > 1.5:
        signals.append("irregular VPN usage pattern")
    if float(row.get("comms_volume_delta", 0) or 0) > 0.5:
        signals.append("significant week-over-week communications spike")
    elif float(row.get("comms_volume_delta", 0) or 0) < -0.3:
        signals.append("sudden drop in communications volume")
    if float(row.get("sentiment_trend", 0) or 0) < -0.2:
        signals.append("declining public sentiment trend")
    if row.get("impossible_travel_flag"):
        signals.append("impossible travel detected (geospatial anomaly)")
    if row.get("clearance_anomaly_flag"):
        signals.append("security clearance status change or reinvestigation flag")
    if not signals:
        signals.append("multi-domain behavioral drift without single dominant signal")
    return "; ".join(signals)


def _case_narrative(row: pd.Series, rank: int) -> str:
    score    = float(row["anomaly_score"])
    pctile   = float(row["anomaly_percentile"])
    domains  = int(row["cross_domain_anomaly_count"])
    signals  = _signal_summary(row)
    window   = row["window_end_date"]
    dept     = row.get("department", "Unknown")
    role     = row.get("role_title", "Unknown")
    clr      = row.get("clearance_level", "Unknown")

    return f"""### Case #{rank}: {row['employee_id']} — {row.get('full_name', 'REDACTED')}

**Risk Profile:** {row['anomaly_tier']} | Score: {score:.4f} (>{pctile:.0f}th percentile)
**Department:** {dept} | **Role:** {role} | **Clearance:** {clr}
**Window:** {window} | **Cluster:** {row['cluster_id']} | **Domains flagged:** {domains}/8

**Signals detected:** {signals}

**Analyst note:** This employee's behavior during the 7-day window ending {window} placed them
in the {pctile:.0f}th percentile of anomaly scores across all 500 employees and 84 rolling windows.
The k-means model (k=5) assigned this employee to cluster {row['cluster_id']}, and their distance
from the cluster centroid ({score:.4f}) indicates behavioral separation from their peer group.
{domains} independent data domains contributed anomalous signals, suggesting a cross-domain
behavioral pattern rather than noise in a single source system.
"""


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def _build_report(
    top_risks: pd.DataFrame,
    cluster_summary: pd.DataFrame,
    tier_signal: pd.DataFrame,
    pipeline_stats: dict,
    now: str,
) -> str:

    lines = [
        "# Executive Analytics — Insider Threat Detection Pipeline",
        f"\n**Report generated:** {now}",
        f"**Model run:** `{pipeline_stats['model_run_id']}`",
        f"**Scored at:** {pipeline_stats['scored_at']}",
        "\n---\n",
        "## Pipeline Summary\n",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Employees analyzed | {pipeline_stats['employees']:,} |",
        f"| Rolling windows evaluated | {pipeline_stats['windows']:,} |",
        f"| Total employee-window records | {pipeline_stats['gold_rows']:,} |",
        f"| Algorithm | k-means (k=5), Euclidean distance from centroid |",
        f"| HIGH tier (>95th pct) | {len(top_risks)} employees in latest window |",
        "\n---\n",
        "## Cluster Population\n",
        "| Cluster | Employees | Avg Score | Max Score | Avg Domains Flagged | HIGH Windows |",
        "|---------|-----------|-----------|-----------|---------------------|--------------|",
    ]
    for _, r in cluster_summary.iterrows():
        lines.append(
            f"| {int(r['cluster_id'])} | {int(r['employees'])} | {float(r['avg_score']):.4f} | "
            f"{float(r['max_score']):.4f} | {float(r['avg_domains_flagged']):.2f} | {int(r['high_windows'])} |"
        )

    lines += [
        "\n---\n",
        "## Domain Signal by Risk Tier\n",
        "| Tier | Windows | Avg AH PACS | Avg AH Network | Avg USB Score | Avg File Movement | Avg VPN | Avg Comms Delta | Avg Sentiment Trend |",
        "|------|---------|-------------|----------------|---------------|-------------------|---------|-----------------|---------------------|",
    ]
    for _, r in tier_signal.iterrows():
        lines.append(
            f"| {r['anomaly_tier']} | {int(r['windows']):,} | "
            f"{float(r['avg_ah_pacs']):.3f} | {float(r['avg_ah_network']):.3f} | "
            f"{float(r['avg_usb_score']):.3f} | {float(r['avg_file_movement']):.3f} | "
            f"{float(r['avg_vpn_score']):.3f} | {float(r['avg_comms_delta']):.3f} | "
            f"{float(r['avg_sentiment_trend']):.3f} |"
        )

    lines += [
        "\n---\n",
        f"## Top {len(top_risks)} HIGH-Risk Employees — Latest Window\n",
        "| Rank | Employee | Department | Clearance | Score | Pctile | Domains Flagged |",
        "|------|----------|------------|-----------|-------|--------|-----------------|",
    ]
    for i, (_, r) in enumerate(top_risks.iterrows(), 1):
        lines.append(
            f"| {i} | {r['employee_id']} | {r.get('department','?')} | "
            f"{r.get('clearance_level','?')} | {float(r['anomaly_score']):.4f} | "
            f"{float(r['anomaly_percentile']):.0f}th | {int(r['cross_domain_anomaly_count'])} |"
        )

    lines += ["\n---\n", "## Individual Case Narratives\n"]
    for i, (_, r) in enumerate(top_risks.head(10).iterrows(), 1):
        lines.append(_case_narrative(r, i))

    lines += [
        "\n---\n",
        "## Methodology Note\n",
        "> Classical ML (k-means unsupervised clustering) identifies employees whose behavioral",
        "> patterns diverge from their peer cluster. The anomaly score is the Euclidean distance",
        "> from the assigned cluster centroid in normalized 9-dimensional feature space.",
        "> No threat labels were used in training — this is a purely signal-driven approach.",
        "> Cross-domain anomaly count is the number of independent data domains (PACS, Network,",
        "> DLP, Comms, PAI, Geo, Adjudication) that contributed an outlier signal in the window.",
        "> HIGH tier: >95th percentile | MEDIUM: 75–95th | LOW: <75th.",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(dry_run: bool = False, env: str = "local", log_level: str = "INFO") -> dict:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    t0 = time.perf_counter()
    logger.info("agent6_analytics START | dry_run=%s env=%s", dry_run, env)

    artifacts: list[str] = []

    try:
        now = datetime.now(timezone.utc).isoformat()

        logger.info("Fetching pipeline stats...")
        pipeline_stats = _fetch_pipeline_stats(env)

        logger.info("Fetching top risks...")
        top_risks = _fetch_top_risks(env, n=25)

        logger.info("Fetching cluster summary...")
        cluster_summary = _fetch_cluster_summary(env)

        logger.info("Fetching tier signal breakdown...")
        tier_signal = _fetch_tier_signal(env)

        logger.info(
            "HIGH-tier employees: %d | Clusters: %d | Gold rows: %d",
            len(top_risks), len(cluster_summary), pipeline_stats["gold_rows"],
        )

        report = _build_report(top_risks, cluster_summary, tier_signal, pipeline_stats, now)

        path = _PROJECT_ROOT / "reports" / "executive_analytics.md"
        if not dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(report, encoding="utf-8")
            logger.info("Executive analytics written: %s", path)
        else:
            logger.info("[DRY-RUN] Would write %d chars to %s", len(report), path)

        artifacts.append(str(path))

        duration = time.perf_counter() - t0
        logger.info("agent6_analytics DONE | duration=%.2fs", duration)

        return {
            "status": "success",
            "rows_in": pipeline_stats["gold_rows"],
            "rows_out": len(top_risks),
            "duration_seconds": round(duration, 3),
            "artifacts": artifacts,
        }

    except Exception as exc:
        duration = time.perf_counter() - t0
        logger.exception("agent6_analytics FAILED: %s", exc)
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
    p = argparse.ArgumentParser(description="agent6_analytics — executive analytics and case narratives")
    p.add_argument("--dry-run",   action="store_true")
    p.add_argument("--env",       default="local", choices=["local", "dev", "prod"])
    p.add_argument("--log-level", default="INFO",  choices=["DEBUG", "INFO", "WARNING"])
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    result = run(dry_run=args.dry_run, env=args.env, log_level=args.log_level)
    print(json.dumps(result, indent=2, default=str))
