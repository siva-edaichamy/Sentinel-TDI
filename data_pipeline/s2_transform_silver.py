"""
s2_transform_silver.py — Identity resolution and Silver-layer conformance.

Reads all Bronze data via Greenplum PXF external tables (ext_*), resolves
native identifiers to employee_id using SQL JOINs on Bronze mapping tables,
and loads each domain into the Silver schema. Also writes Parquet snapshots
to /data/silver/ by reading back from the Silver tables after load.

Identity resolution (pure SQL inside GP):
  sv_pacs        : badge_id → employee_id via ext_badge_registry
  sv_network     : machine_id → employee_id via ext_asset_assignment (most-recent wins)
  sv_dlp         : machine_id → employee_id via ext_asset_assignment
  sv_comms       : email_address → employee_id via ext_directory
  sv_pai         : social_handle → employee_id via ext_social_handle_map
  sv_geo         : badge_id → employee_id via ext_badge_registry
  sv_adjudication: direct (employee_id native)
  sv_hris        : direct (employee_id native)

Unresolved records → sv_unresolved_events (dead-letter table).
Raises RuntimeError if resolution rate < 90% for any domain.
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from dotenv import load_dotenv

from agents.db import get_connection

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

SILVER_DIR       = _PROJECT_ROOT / "data" / "silver"
PIPELINE_VERSION = os.getenv("PIPELINE_VERSION", "s2_silver_v2")
BRONZE_SCHEMA    = "insider_threat_bronze"
SILVER_SCHEMA    = "insider_threat_silver"
MIN_RESOLUTION_RATE = 0.90

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_parquet(df: pd.DataFrame, name: str, dry_run: bool) -> str:
    path = SILVER_DIR / f"{name}.parquet"
    if dry_run:
        logger.info("[DRY-RUN] Would write %d rows → %s", len(df), path)
    else:
        SILVER_DIR.mkdir(parents=True, exist_ok=True)
        table = pa.Table.from_pandas(df, preserve_index=False)
        pq.write_table(table, path, compression="snappy")
        logger.info("Wrote %d rows → %s", len(df), path)
    return str(path)


def _read_silver_table(env: str, table: str) -> pd.DataFrame:
    """Read a Silver table back from GP for Parquet snapshot."""
    with get_connection(env) as conn:
        return pd.read_sql(f"SELECT * FROM {SILVER_SCHEMA}.{table}", conn)


def _check_resolution_rate(domain: str, total: int, resolved: int) -> None:
    if total == 0:
        return
    rate = resolved / total
    logger.info("  %s resolution: %.1f%% (%d/%d)", domain, rate * 100, resolved, total)
    if rate < MIN_RESOLUTION_RATE:
        raise RuntimeError(
            f"Identity resolution rate for {domain} is {rate:.1%} "
            f"— below minimum {MIN_RESOLUTION_RATE:.0%}. Halting pipeline."
        )


def _exec(cur, sql: str) -> int:
    """Execute SQL, return rowcount."""
    cur.execute(sql)
    return cur.rowcount


# ---------------------------------------------------------------------------
# SQL — one INSERT per domain (resolved) + one INSERT per domain (unresolved)
# All identity resolution happens as SQL JOINs on ext_* tables inside GP.
# ---------------------------------------------------------------------------

def _sql_hris(ingested_at: str) -> tuple[str, str]:
    """HRIS — direct (employee_id native, no join needed)."""
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_hris (
            employee_id, event_date, event_timestamp,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            full_name, department, role_title, role_peer_group,
            clearance_level, employment_status, start_date, end_date
        )
        SELECT
            employee_id,
            start_date                                               AS event_date,
            start_date::TIMESTAMPTZ                                  AS event_timestamp,
            'hris'                                                   AS source_domain,
            'hris_events.csv'                                        AS source_file,
            md5(employee_id || '|' || full_name || '|'
                || COALESCE(department,''))                          AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            full_name, department, role_title, role_peer_group,
            clearance_level, employment_status,
            start_date,
            end_date
        FROM {BRONZE_SCHEMA}.ext_hris_events
    """
    # HRIS is authoritative — no unresolved path
    unresolved = ""
    return resolved, unresolved


def _sql_pacs(ingested_at: str) -> tuple[str, str]:
    """PACS — badge_id → employee_id via ext_badge_registry."""
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_pacs (
            employee_id, event_date, event_timestamp,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            door_id, location_name, building_code, direction,
            after_hours_flag, weekend_flag
        )
        SELECT
            br.employee_id,
            p.event_timestamp::DATE                                  AS event_date,
            p.event_timestamp,
            'pacs'                                                   AS source_domain,
            'pacs_events.csv'                                        AS source_file,
            md5(p.badge_id || '|' || p.event_timestamp::text
                || '|' || COALESCE(p.door_id,''))                   AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            p.door_id, p.location_name, p.building_code, p.direction,
            p.after_hours                                            AS after_hours_flag,
            p.weekend                                                AS weekend_flag
        FROM {BRONZE_SCHEMA}.ext_pacs_events p
        JOIN {BRONZE_SCHEMA}.ext_badge_registry br ON p.badge_id = br.badge_id
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'pacs', 'pacs_events.csv', p.badge_id, 'badge_id',
            md5(p.badge_id || '|' || p.event_timestamp::text),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            p.badge_id || '|' || p.event_timestamp::text
                || '|' || COALESCE(p.building_code,'')
        FROM {BRONZE_SCHEMA}.ext_pacs_events p
        LEFT JOIN {BRONZE_SCHEMA}.ext_badge_registry br ON p.badge_id = br.badge_id
        WHERE br.badge_id IS NULL
    """
    return resolved, unresolved


def _sql_network(ingested_at: str) -> tuple[str, str]:
    """Network — machine_id → employee_id via ext_asset_assignment (most-recent wins)."""
    latest_asgn = f"""
        SELECT machine_id, employee_id
        FROM (
            SELECT machine_id, employee_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY machine_id
                       ORDER BY effective_start DESC NULLS LAST
                   ) AS rn
            FROM {BRONZE_SCHEMA}.ext_asset_assignment
        ) t WHERE rn = 1
    """
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_network (
            employee_id, event_date, event_timestamp,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            machine_id, ip_address, event_type, vpn_flag,
            dns_query_domain, bytes_transferred, session_duration_min,
            after_hours_flag
        )
        SELECT
            la.employee_id,
            n.event_timestamp::DATE                                  AS event_date,
            n.event_timestamp,
            'network'                                                AS source_domain,
            'network_events.csv'                                     AS source_file,
            md5(n.machine_id || '|' || n.ip_address || '|'
                || n.event_timestamp::text)                          AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            n.machine_id, n.ip_address, n.event_type, n.vpn_flag,
            n.dns_query_domain, n.bytes_transferred,
            n.session_duration_min,
            n.after_hours                                            AS after_hours_flag
        FROM {BRONZE_SCHEMA}.ext_network_events n
        JOIN ({latest_asgn}) la ON n.machine_id = la.machine_id
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'network', 'network_events.csv', n.machine_id, 'machine_id',
            md5(n.machine_id || '|' || n.event_timestamp::text),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            n.machine_id || '|' || n.ip_address || '|' || n.event_timestamp::text
        FROM {BRONZE_SCHEMA}.ext_network_events n
        LEFT JOIN ({latest_asgn}) la ON n.machine_id = la.machine_id
        WHERE la.machine_id IS NULL
    """
    return resolved, unresolved


def _sql_dlp(ingested_at: str) -> tuple[str, str]:
    """DLP — machine_id → employee_id via ext_asset_assignment (most-recent wins)."""
    latest_asgn = f"""
        SELECT machine_id, employee_id
        FROM (
            SELECT machine_id, employee_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY machine_id
                       ORDER BY effective_start DESC NULLS LAST
                   ) AS rn
            FROM {BRONZE_SCHEMA}.ext_asset_assignment
        ) t WHERE rn = 1
    """
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_dlp (
            employee_id, event_date, event_timestamp,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            machine_id, event_type, file_name, file_extension,
            file_size_mb, destination_type,
            usb_flag, print_flag, cloud_upload_flag
        )
        SELECT
            la.employee_id,
            d.event_timestamp::DATE                                  AS event_date,
            d.event_timestamp,
            'dlp'                                                    AS source_domain,
            'dlp_events.csv'                                         AS source_file,
            md5(d.machine_id || '|' || d.user_account || '|'
                || d.event_timestamp::text)                          AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            d.machine_id, d.event_type, d.file_name, d.file_extension,
            d.file_size_mb, d.destination_type,
            d.usb_flag, d.print_flag, d.cloud_upload_flag
        FROM {BRONZE_SCHEMA}.ext_dlp_events d
        JOIN ({latest_asgn}) la ON d.machine_id = la.machine_id
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'dlp', 'dlp_events.csv', d.machine_id, 'machine_id',
            md5(d.machine_id || '|' || d.event_timestamp::text),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            d.machine_id || '|' || d.user_account || '|' || d.event_timestamp::text
        FROM {BRONZE_SCHEMA}.ext_dlp_events d
        LEFT JOIN ({latest_asgn}) la ON d.machine_id = la.machine_id
        WHERE la.machine_id IS NULL
    """
    return resolved, unresolved


def _sql_comms(ingested_at: str) -> tuple[str, str]:
    """Comms — email_address → employee_id via ext_directory."""
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_comms (
            employee_id, event_date, event_timestamp,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            channel_type, recipient_count, external_recipient_flag,
            attachment_flag, attachment_size_mb, after_hours_flag
        )
        SELECT
            dir.employee_id,
            c.event_timestamp::DATE                                  AS event_date,
            c.event_timestamp,
            'comms'                                                  AS source_domain,
            'comms_events.csv'                                       AS source_file,
            md5(c.email_address || '|' || c.event_timestamp::text
                || '|' || c.channel_type)                           AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            c.channel_type,
            c.recipient_count::INT,
            c.external_recipient_flag,
            c.attachment_flag,
            c.attachment_size_mb,
            c.after_hours                                            AS after_hours_flag
        FROM {BRONZE_SCHEMA}.ext_comms_events c
        JOIN {BRONZE_SCHEMA}.ext_directory dir ON c.email_address = dir.email_address
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'comms', 'comms_events.csv', c.email_address, 'email_address',
            md5(c.email_address || '|' || c.event_timestamp::text),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            c.email_address || '|' || c.channel_type || '|' || c.event_timestamp::text
        FROM {BRONZE_SCHEMA}.ext_comms_events c
        LEFT JOIN {BRONZE_SCHEMA}.ext_directory dir ON c.email_address = dir.email_address
        WHERE dir.email_address IS NULL
    """
    return resolved, unresolved


def _sql_pai(ingested_at: str) -> tuple[str, str]:
    """PAI — social_handle → employee_id via ext_social_handle_map (~5% null employee_id)."""
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_pai (
            employee_id, event_date, event_timestamp,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            platform, sentiment_score, post_count, engagement_count
        )
        SELECT
            sm.employee_id,
            p.event_timestamp::DATE                                  AS event_date,
            p.event_timestamp,
            'pai'                                                    AS source_domain,
            'pai_events.csv'                                         AS source_file,
            md5(p.social_handle || '|' || p.event_timestamp::text)  AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            p.platform,
            p.sentiment_score,
            p.post_count::INT,
            p.engagement_count::INT
        FROM {BRONZE_SCHEMA}.ext_pai_events p
        JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
            ON p.social_handle = sm.social_handle
            AND sm.employee_id IS NOT NULL
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'pai', 'pai_events.csv', p.social_handle, 'social_handle',
            md5(p.social_handle || '|' || p.event_timestamp::text),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            p.social_handle || '|' || p.platform || '|' || p.event_timestamp::text
        FROM {BRONZE_SCHEMA}.ext_pai_events p
        LEFT JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
            ON p.social_handle = sm.social_handle
            AND sm.employee_id IS NOT NULL
        WHERE sm.social_handle IS NULL
    """
    return resolved, unresolved


def _sql_geo(ingested_at: str) -> tuple[str, str]:
    """Geo — badge_id → employee_id via ext_badge_registry."""
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_geo (
            employee_id, event_date, event_timestamp,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            building_code, latitude, longitude, device_type
        )
        SELECT
            br.employee_id,
            g.event_timestamp::DATE                                  AS event_date,
            g.event_timestamp,
            'geo'                                                    AS source_domain,
            'geo_events.csv'                                         AS source_file,
            md5(g.badge_id || '|' || g.device_id || '|'
                || g.event_timestamp::text)                         AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            g.building_code, g.latitude, g.longitude, g.device_type
        FROM {BRONZE_SCHEMA}.ext_geo_events g
        JOIN {BRONZE_SCHEMA}.ext_badge_registry br ON g.badge_id = br.badge_id
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'geo', 'geo_events.csv', g.badge_id, 'badge_id',
            md5(g.badge_id || '|' || g.event_timestamp::text),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            g.badge_id || '|' || g.device_id || '|' || g.event_timestamp::text
        FROM {BRONZE_SCHEMA}.ext_geo_events g
        LEFT JOIN {BRONZE_SCHEMA}.ext_badge_registry br ON g.badge_id = br.badge_id
        WHERE br.badge_id IS NULL
    """
    return resolved, unresolved


def _sql_adjudication(ingested_at: str) -> tuple[str, str]:
    """Adjudication — direct (employee_id native)."""
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_adjudication (
            employee_id, event_date, event_timestamp,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            clearance_level, clearance_status, investigation_flag,
            reinvestigation_due_date, status_change_flag
        )
        SELECT
            employee_id,
            event_timestamp::DATE                                    AS event_date,
            event_timestamp,
            'adjudication'                                           AS source_domain,
            'adjudication_events.csv'                                AS source_file,
            md5(employee_id || '|' || event_timestamp::text
                || '|' || clearance_status)                         AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            clearance_level, clearance_status,
            investigation_flag,
            CASE WHEN reinvestigation_due_date IS NOT NULL
                 THEN reinvestigation_due_date::DATE ELSE NULL END,
            status_change_flag
        FROM {BRONZE_SCHEMA}.ext_adjudication_events
    """
    return resolved, ""


# ---------------------------------------------------------------------------
# Core executor
# ---------------------------------------------------------------------------

def _resolve_domain(
    env: str,
    domain: str,
    resolved_sql: str,
    unresolved_sql: str,
    dry_run: bool,
) -> tuple[int, int]:
    """
    TRUNCATE the Silver table, execute the resolved INSERT, then the unresolved INSERT.
    Returns (resolved_count, unresolved_count).
    """
    silver_table = f"{SILVER_SCHEMA}.sv_{domain}"

    if dry_run:
        logger.info("[DRY-RUN] Would resolve %s via SQL in GP", domain)
        return 0, 0

    with get_connection(env) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f"TRUNCATE {silver_table}")
            cur.execute(resolved_sql)
            resolved_n = cur.rowcount

            unresolved_n = 0
            if unresolved_sql:
                cur.execute(unresolved_sql)
                unresolved_n = cur.rowcount

    logger.info("  %s: resolved=%d unresolved=%d", domain, resolved_n, unresolved_n)
    return resolved_n, unresolved_n


# ---------------------------------------------------------------------------
# Silver lineage schema doc
# ---------------------------------------------------------------------------

def _write_lineage_map(domains: list[str], dry_run: bool) -> None:
    schema = {
        "generated_at": _now(),
        "identity_resolution": "pure SQL JOINs on GP ext_* external tables (PXF → MinIO)",
        "lineage_columns": [
            "employee_id", "event_date", "event_timestamp", "source_domain",
            "source_file", "record_hash", "ingested_at", "transformed_at",
            "pipeline_version", "identity_resolution_status",
        ],
        "tables": {d: f"{SILVER_SCHEMA}.sv_{d}" for d in domains},
        "dead_letter": f"{SILVER_SCHEMA}.sv_unresolved_events",
        "resolution_threshold": MIN_RESOLUTION_RATE,
    }
    path = _PROJECT_ROOT / "schema" / "silver_lineage_map.json"
    if not dry_run:
        path.write_text(json.dumps(schema, indent=2))
    logger.info("Silver lineage map: %s", path)


# ---------------------------------------------------------------------------
# run_domain() — single-domain entry point for Airflow parallel tasks
# ---------------------------------------------------------------------------

_DOMAIN_SQL_MAP = {
    "hris":         _sql_hris,
    "pacs":         _sql_pacs,
    "network":      _sql_network,
    "dlp":          _sql_dlp,
    "comms":        _sql_comms,
    "pai":          _sql_pai,
    "geo":          _sql_geo,
    "adjudication": _sql_adjudication,
}


def run_domain(domain: str, dry_run: bool = False, env: str = "local",
               log_level: str = "INFO") -> dict:
    """
    Resolve and load a single Silver domain.
    Called by the Airflow DAG for each domain task running in parallel.
    Returns standard agent result dict.
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    if domain not in _DOMAIN_SQL_MAP:
        raise ValueError(f"Unknown domain: {domain}. Must be one of {list(_DOMAIN_SQL_MAP)}")

    t0 = time.perf_counter()
    logger.info("s2_transform_silver [%s] START | dry_run=%s env=%s", domain, dry_run, env)

    ingested_at = _now()
    sql_fn = _DOMAIN_SQL_MAP[domain]
    resolved_sql, unresolved_sql = sql_fn(ingested_at)

    resolved_n, unresolved_n = _resolve_domain(env, domain, resolved_sql, unresolved_sql, dry_run)
    total = resolved_n + unresolved_n
    _check_resolution_rate(domain, total, resolved_n)

    artifacts = []
    if not dry_run:
        df = _read_silver_table(env, f"sv_{domain}")
        artifacts.append(_write_parquet(df, f"sv_{domain}", dry_run=False))

    duration = time.perf_counter() - t0
    logger.info("s2_transform_silver [%s] DONE | resolved=%d unresolved=%d duration=%.2fs",
                domain, resolved_n, unresolved_n, duration)
    return {
        "status": "success",
        "rows_in": total,
        "rows_out": resolved_n,
        "duration_seconds": round(duration, 3),
        "artifacts": artifacts,
        "domain": domain,
    }


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(dry_run: bool = False, env: str = "local", log_level: str = "INFO") -> dict:
    """
    Resolve identities via SQL and load all Silver domain tables in Greenplum.
    Reads Bronze data from ext_* PXF external tables — no local file reads.

    Returns standard agent result dict.
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    t0 = time.perf_counter()
    logger.info("s2_transform_silver START | dry_run=%s env=%s", dry_run, env)

    artifacts: list[str] = []
    rows_in  = 0
    rows_out = 0
    total_unresolved = 0

    try:
        ingested_at = _now()

        # Clear dead-letter table once before any domain runs
        if not dry_run:
            with get_connection(env) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute(f"TRUNCATE {SILVER_SCHEMA}.sv_unresolved_events")

        # Domain registry: name → (resolved_sql, unresolved_sql)
        domain_sqls = {
            "hris":         _sql_hris(ingested_at),
            "pacs":         _sql_pacs(ingested_at),
            "network":      _sql_network(ingested_at),
            "dlp":          _sql_dlp(ingested_at),
            "comms":        _sql_comms(ingested_at),
            "pai":          _sql_pai(ingested_at),
            "geo":          _sql_geo(ingested_at),
            "adjudication": _sql_adjudication(ingested_at),
        }

        for domain, (resolved_sql, unresolved_sql) in domain_sqls.items():
            logger.info("Resolving %s in GP...", domain)
            resolved_n, unresolved_n = _resolve_domain(
                env, domain, resolved_sql, unresolved_sql, dry_run
            )

            total = resolved_n + unresolved_n
            rows_in          += total
            rows_out         += resolved_n
            total_unresolved += unresolved_n

            _check_resolution_rate(domain, total, resolved_n)

            # Write Parquet snapshot from GP Silver table
            if not dry_run:
                df = _read_silver_table(env, f"sv_{domain}")
                parquet_path = _write_parquet(df, f"sv_{domain}", dry_run=False)
            else:
                parquet_path = str(SILVER_DIR / f"sv_{domain}.parquet")
            artifacts.append(parquet_path)

        _write_lineage_map(list(domain_sqls.keys()), dry_run)

        duration = time.perf_counter() - t0
        logger.info(
            "s2_transform_silver DONE | rows_in=%d rows_out=%d unresolved=%d duration=%.2fs",
            rows_in, rows_out, total_unresolved, duration,
        )

        return {
            "status": "success",
            "rows_in": rows_in,
            "rows_out": rows_out,
            "duration_seconds": round(duration, 3),
            "artifacts": artifacts,
        }

    except Exception as exc:
        duration = time.perf_counter() - t0
        logger.exception("s2_transform_silver FAILED: %s", exc)
        return {
            "status": "failure",
            "rows_in": rows_in,
            "rows_out": rows_out,
            "duration_seconds": round(duration, 3),
            "artifacts": artifacts,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="s2_transform_silver — identity resolution and conformance")
    p.add_argument("--dry-run",   action="store_true")
    p.add_argument("--env",       default="local", choices=["local", "dev", "prod"])
    p.add_argument("--log-level", default="INFO",  choices=["DEBUG", "INFO", "WARNING"])
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    result = run(dry_run=args.dry_run, env=args.env, log_level=args.log_level)
    print(json.dumps(result, indent=2))
