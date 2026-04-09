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

from db import get_connection

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


_OSINT_RESOLUTION_RATE = 0.30  # OSINT streams are inherently noisy

def _check_resolution_rate(domain: str, total: int, resolved: int) -> None:
    if total == 0:
        return
    rate = resolved / total
    threshold = _OSINT_RESOLUTION_RATE if domain.startswith("osint_") else MIN_RESOLUTION_RATE
    logger.info("  %s resolution: %.1f%% (%d/%d)", domain, rate * 100, resolved, total)
    if rate < threshold:
        raise RuntimeError(
            f"Identity resolution rate for {domain} is {rate:.1%} "
            f"— below minimum {threshold:.0%}. Halting pipeline."
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
# OSINT Silver SQL — 5 new streams
# ---------------------------------------------------------------------------

def _sql_osint_twitter(ingested_at: str) -> tuple[str, str]:
    """
    Twitter — UPDATE sv_pai to populate emotion_tags and keyword_flags.
    Identity: tweet handle → employee_id via ext_social_handle_map.
    No TRUNCATE — sv_pai already populated by the 'pai' internal domain.
    """
    update = f"""
        WITH tweet_daily AS (
            SELECT
                sm.employee_id,
                tw.scraped_datetime::DATE                        AS event_date,
                string_agg(tw.tweet_text, ' ')                   AS combined_text
            FROM {BRONZE_SCHEMA}.ext_raw_tweets tw
            JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
                ON tw.handle = sm.social_handle
                AND sm.employee_id IS NOT NULL
            GROUP BY sm.employee_id, tw.scraped_datetime::DATE
        )
        UPDATE {SILVER_SCHEMA}.sv_pai sp
        SET
            emotion_tags = ARRAY_REMOVE(ARRAY[
                CASE WHEN td.combined_text ILIKE '%frustr%'   OR td.combined_text ILIKE '%angry%'
                          OR td.combined_text ILIKE '%rage%'                     THEN 'frustration'   END,
                CASE WHEN td.combined_text ILIKE '%unfair%'   OR td.combined_text ILIKE '%betray%'
                          OR td.combined_text ILIKE '%resentment%'               THEN 'grievance'     END,
                CASE WHEN td.combined_text ILIKE '%quit%'     OR td.combined_text ILIKE '%leaving%'
                          OR td.combined_text ILIKE '%resign%'                   THEN 'disengagement' END,
                CASE WHEN td.combined_text ILIKE '%depress%'  OR td.combined_text ILIKE '%hopeless%'
                          OR td.combined_text ILIKE '%stress%'                   THEN 'distress'      END,
                CASE WHEN td.combined_text ILIKE '%steal%'    OR td.combined_text ILIKE '%revenge%'
                          OR td.combined_text ILIKE '%payback%'                  THEN 'hostility'     END
            ], NULL),
            keyword_flags = ARRAY_REMOVE(ARRAY[
                CASE WHEN td.combined_text ILIKE '%secret%'        OR td.combined_text ILIKE '%confidential%'
                                                                                   THEN 'sensitive_terms'    END,
                CASE WHEN td.combined_text ILIKE '%money%'         OR td.combined_text ILIKE '%debt%'
                          OR td.combined_text ILIKE '%bankrupt%'                   THEN 'financial_stress'   END,
                CASE WHEN td.combined_text ILIKE '%fired%'         OR td.combined_text ILIKE '%unemployed%'
                          OR td.combined_text ILIKE '%looking for work%'           THEN 'employment_concern' END,
                CASE WHEN td.combined_text ILIKE '%recruiter%'     OR td.combined_text ILIKE '%new opportunity%'
                                                                                   THEN 'job_seeking'        END
            ], NULL)
        FROM tweet_daily td
        WHERE sp.employee_id = td.employee_id
          AND sp.event_date  = td.event_date
    """
    return update, ""


def _sql_osint_instagram(ingested_at: str) -> tuple[str, str]:
    """
    Instagram — INSERT silver_geo_anomalies.
    Identity: post handle → employee_id via ext_social_handle_map.
    Location classification and anomaly flagging done in SQL.
    """
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.silver_geo_anomalies (
            post_id, event_date, employee_id,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            classified_location_type, anomaly_flag,
            work_hours_flag, incongruity_flag
        )
        SELECT
            ig.post_id,
            ig.scraped_datetime::DATE                                AS event_date,
            sm.employee_id,
            'instagram'                                              AS source_domain,
            'raw_instagram_posts.csv'                                AS source_file,
            md5(ig.post_id || '|' || ig.handle)                     AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            CASE
                WHEN ig.location_string ILIKE '%embassy%'    OR ig.location_string ILIKE '%pentagon%'
                  OR ig.location_string ILIKE '%military%'   OR ig.location_string ILIKE '%fort %'
                  OR ig.location_string ILIKE '%base%'                           THEN 'sensitive_government'
                WHEN ig.location_string ILIKE '%airport%'    OR ig.location_string ILIKE '%international%'
                  OR ig.location_string ILIKE '%terminal%'                       THEN 'travel_hub'
                WHEN ig.location_lat IS NOT NULL
                  AND (ig.location_lat < 38.5 OR ig.location_lat > 39.1
                    OR ig.location_lon < -77.5 OR ig.location_lon > -76.8)      THEN 'unusual_travel'
                WHEN ig.post_type = 'check_in'                                   THEN 'standard_checkin'
                ELSE                                                                  'standard'
            END                                                      AS classified_location_type,
            CASE
                WHEN ig.location_string ILIKE '%embassy%'  OR ig.location_string ILIKE '%pentagon%'
                  OR ig.location_string ILIKE '%military%' OR ig.location_string ILIKE '%fort %'
                  OR ig.location_string ILIKE '%base%'
                  OR (ig.location_lat IS NOT NULL
                      AND (ig.location_lat < 38.5 OR ig.location_lat > 39.1
                        OR ig.location_lon < -77.5 OR ig.location_lon > -76.8)) THEN TRUE
                ELSE FALSE
            END                                                      AS anomaly_flag,
            EXTRACT(HOUR FROM ig.scraped_datetime) BETWEEN 9 AND 17  AS work_hours_flag,
            CASE
                WHEN ig.location_string ILIKE '%casino%'   OR ig.location_string ILIKE '%luxury%'
                  OR ig.location_string ILIKE '%yacht%'    OR ig.location_string ILIKE '%resort%'
                  OR ig.location_string ILIKE '%five star%'                      THEN TRUE
                ELSE FALSE
            END                                                      AS incongruity_flag
        FROM {BRONZE_SCHEMA}.ext_raw_instagram_posts ig
        JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
            ON ig.handle = sm.social_handle
            AND sm.employee_id IS NOT NULL
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'instagram', 'raw_instagram_posts.csv', ig.handle, 'social_handle',
            md5(ig.post_id || '|' || ig.handle),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            ig.post_id || '|' || ig.handle || '|' || ig.scraped_datetime::text
        FROM {BRONZE_SCHEMA}.ext_raw_instagram_posts ig
        LEFT JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
            ON ig.handle = sm.social_handle AND sm.employee_id IS NOT NULL
        WHERE sm.social_handle IS NULL
    """
    return resolved, unresolved


def _sql_osint_lifestyle(ingested_at: str) -> tuple[str, str]:
    """
    Lifestyle signals — INSERT silver_lifestyle_incongruity.
    Identity: signal handle → employee_id via ext_social_handle_map.
    Joins sv_hris for salary_band derivation and incongruity scoring.
    """
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.silver_lifestyle_incongruity (
            signal_id, event_date, employee_id,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            signal_type, estimated_value_usd,
            salary_band, incongruity_score, cumulative_30day_spend
        )
        WITH base AS (
            SELECT
                ls.signal_id,
                ls.scraped_datetime::DATE                            AS event_date,
                sm.employee_id,
                ls.signal_source                                     AS signal_type,
                COALESCE(ls.estimated_value_usd, 0)                  AS estimated_value_usd,
                CASE
                    WHEN h.role_title ILIKE '%senior%'    OR h.role_title ILIKE '%director%'
                      OR h.role_title ILIKE '%chief%'     OR h.role_title ILIKE '% vp%'
                      OR h.role_title ILIKE '%executive%' OR h.role_title ILIKE '%principal%'
                                                                     THEN 'senior'
                    WHEN h.role_title ILIKE '%manager%'   OR h.role_title ILIKE '%lead%'
                      OR h.role_title ILIKE '%analyst%'   OR h.role_title ILIKE '%engineer%'
                                                                     THEN 'mid'
                    ELSE                                                  'low'
                END                                                  AS salary_band,
                md5(ls.signal_id || '|' || sm.employee_id)           AS record_hash
            FROM {BRONZE_SCHEMA}.ext_raw_lifestyle_signals ls
            JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
                ON ls.handle = sm.social_handle AND sm.employee_id IS NOT NULL
            LEFT JOIN {SILVER_SCHEMA}.sv_hris h USING (employee_id)
        )
        SELECT
            b.signal_id, b.event_date, b.employee_id,
            'lifestyle'                                              AS source_domain,
            'raw_lifestyle_signals.csv'                              AS source_file,
            b.record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            b.signal_type,
            b.estimated_value_usd,
            b.salary_band,
            ROUND(CAST(b.estimated_value_usd AS FLOAT8) /
                CASE b.salary_band
                    WHEN 'senior' THEN 5000.0
                    WHEN 'mid'    THEN 2000.0
                    ELSE               1000.0
                END, 4)                                              AS incongruity_score,
            SUM(b.estimated_value_usd) OVER (
                PARTITION BY b.employee_id
                ORDER BY b.event_date
                ROWS BETWEEN 29 PRECEDING AND CURRENT ROW
            )                                                        AS cumulative_30day_spend
        FROM base b
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'lifestyle', 'raw_lifestyle_signals.csv', ls.handle, 'social_handle',
            md5(ls.signal_id || '|' || ls.handle),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            ls.signal_id || '|' || ls.handle || '|' || ls.scraped_datetime::text
        FROM {BRONZE_SCHEMA}.ext_raw_lifestyle_signals ls
        LEFT JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
            ON ls.handle = sm.social_handle AND sm.employee_id IS NOT NULL
        WHERE sm.social_handle IS NULL
    """
    return resolved, unresolved


def _sql_osint_financial(ingested_at: str) -> tuple[str, str]:
    """
    Financial stress — INSERT silver_financial_stress.
    Identity: direct (employee_id native in Bronze).
    record_type and amount_usd parsed from raw_json.
    stress_score and cumulative computed via window function.
    """
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.silver_financial_stress (
            record_id, event_date, employee_id,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            record_type, amount_usd,
            stress_score, cumulative_stress_score
        )
        WITH base AS (
            SELECT
                fs.record_id,
                fs.scraped_datetime::DATE                            AS event_date,
                fs.employee_id,
                COALESCE(fs.raw_json::json->>'type', fs.source)      AS record_type,
                COALESCE((fs.raw_json::json->>'amount')::INT, 0)     AS amount_usd,
                md5(fs.record_id || '|' || fs.employee_id)           AS record_hash,
                CASE COALESCE(fs.raw_json::json->>'type', fs.source)
                    WHEN 'bankruptcy_filing' THEN 1.0
                    WHEN 'lien'              THEN 0.7
                    WHEN 'eviction_notice'   THEN 0.6
                    WHEN 'civil_judgment'    THEN 0.5
                    ELSE                          0.3
                END                                                  AS stress_score
            FROM {BRONZE_SCHEMA}.ext_raw_financial_stress fs
        )
        SELECT
            b.record_id, b.event_date, b.employee_id,
            'financial_stress'                                       AS source_domain,
            'raw_financial_stress.csv'                               AS source_file,
            b.record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            b.record_type,
            b.amount_usd,
            b.stress_score,
            SUM(b.stress_score) OVER (
                PARTITION BY b.employee_id
                ORDER BY b.event_date
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
            )                                                        AS cumulative_stress_score
        FROM base b
    """
    # Financial stress uses employee_id directly — no unresolved path
    return resolved, ""


def _sql_osint_darkweb(ingested_at: str) -> tuple[str, str]:
    """
    Dark web signals — INSERT silver_darkweb_signals.
    Identity: dual-path — email → ext_directory OR social_handle → ext_social_handle_map.
    signal_type, severity parsed from raw_json; confidence_score derived from severity.
    """
    resolved = f"""
        INSERT INTO {SILVER_SCHEMA}.silver_darkweb_signals (
            detection_id, event_date, employee_id,
            source_domain, source_file, record_hash,
            ingested_at, transformed_at, pipeline_version,
            identity_resolution_status,
            signal_type, severity, confidence_score, matched_on
        )
        SELECT
            dw.detection_id,
            dw.scraped_datetime::DATE                                AS event_date,
            COALESCE(dir.employee_id, sm.employee_id)               AS employee_id,
            'darkweb'                                                AS source_domain,
            'raw_darkweb_signals.csv'                                AS source_file,
            md5(dw.detection_id || '|' || dw.handle)               AS record_hash,
            '{ingested_at}'::TIMESTAMPTZ                             AS ingested_at,
            NOW()                                                    AS transformed_at,
            '{PIPELINE_VERSION}'                                     AS pipeline_version,
            'RESOLVED'                                               AS identity_resolution_status,
            COALESCE(dw.raw_json::json->>'type', dw.signal_source)  AS signal_type,
            COALESCE(dw.raw_json::json->>'severity', 'low')         AS severity,
            CASE COALESCE(dw.raw_json::json->>'severity', 'low')
                WHEN 'high'   THEN 0.75 + (ABS(hashtext(dw.detection_id)) % 20) / 100.0
                WHEN 'medium' THEN 0.45 + (ABS(hashtext(dw.detection_id)) % 30) / 100.0
                ELSE               0.15 + (ABS(hashtext(dw.detection_id)) % 25) / 100.0
            END                                                      AS confidence_score,
            dw.matched_on
        FROM {BRONZE_SCHEMA}.ext_raw_darkweb_signals dw
        LEFT JOIN {BRONZE_SCHEMA}.ext_directory dir
            ON dw.matched_on = 'email' AND dw.handle = dir.email_address
        LEFT JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
            ON dw.matched_on = 'social_handle' AND dw.handle = sm.social_handle
            AND sm.employee_id IS NOT NULL
        WHERE COALESCE(dir.employee_id, sm.employee_id) IS NOT NULL
    """
    unresolved = f"""
        INSERT INTO {SILVER_SCHEMA}.sv_unresolved_events (
            source_domain, source_file, raw_identifier, identifier_type,
            record_hash, identity_resolution_status,
            ingested_at, pipeline_version, raw_record
        )
        SELECT
            'darkweb', 'raw_darkweb_signals.csv', dw.handle, dw.matched_on,
            md5(dw.detection_id || '|' || dw.handle),
            'UNRESOLVED',
            '{ingested_at}'::TIMESTAMPTZ,
            '{PIPELINE_VERSION}',
            dw.detection_id || '|' || dw.handle || '|' || dw.scraped_datetime::text
        FROM {BRONZE_SCHEMA}.ext_raw_darkweb_signals dw
        LEFT JOIN {BRONZE_SCHEMA}.ext_directory dir
            ON dw.matched_on = 'email' AND dw.handle = dir.email_address
        LEFT JOIN {BRONZE_SCHEMA}.ext_social_handle_map sm
            ON dw.matched_on = 'social_handle' AND dw.handle = sm.social_handle
            AND sm.employee_id IS NOT NULL
        WHERE COALESCE(dir.employee_id, sm.employee_id) IS NULL
    """
    return resolved, unresolved


# ---------------------------------------------------------------------------
# Core executor
# ---------------------------------------------------------------------------

def _resolve_domain(
    env: str,
    domain: str,
    resolved_sql: str,
    unresolved_sql: str,
    dry_run: bool,
    table_override: str | None = None,
    skip_truncate: bool = False,
) -> tuple[int, int]:
    """
    TRUNCATE the Silver table, execute the resolved INSERT, then the unresolved INSERT.
    Returns (resolved_count, unresolved_count).
    table_override: use a specific fully-qualified table name instead of sv_{domain}.
    skip_truncate: do not truncate before inserting (used for UPDATE-mode OSINT domains).
    """
    silver_table = table_override or f"{SILVER_SCHEMA}.sv_{domain}"

    if dry_run:
        logger.info("[DRY-RUN] Would resolve %s via SQL in GP", domain)
        return 0, 0

    with get_connection(env) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            if not skip_truncate:
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
    # OSINT streams
    "osint_twitter":    _sql_osint_twitter,
    "osint_instagram":  _sql_osint_instagram,
    "osint_lifestyle":  _sql_osint_lifestyle,
    "osint_financial":  _sql_osint_financial,
    "osint_darkweb":    _sql_osint_darkweb,
}

# OSINT domains: maps domain key → (silver_table_name, skip_truncate)
# skip_truncate=True for twitter because it UPDATEs sv_pai rather than INSERTing a new table
_OSINT_TABLE_MAP: dict[str, tuple[str, bool]] = {
    "osint_twitter":   (f"{SILVER_SCHEMA}.sv_pai",                       True),
    "osint_instagram": (f"{SILVER_SCHEMA}.silver_geo_anomalies",         False),
    "osint_lifestyle": (f"{SILVER_SCHEMA}.silver_lifestyle_incongruity",  False),
    "osint_financial": (f"{SILVER_SCHEMA}.silver_financial_stress",       False),
    "osint_darkweb":   (f"{SILVER_SCHEMA}.silver_darkweb_signals",        False),
}

# Parquet output name for each OSINT domain (file in /data/silver/)
_OSINT_PARQUET_NAME: dict[str, str] = {
    "osint_twitter":   "sv_pai_osint",
    "osint_instagram": "silver_geo_anomalies",
    "osint_lifestyle": "silver_lifestyle_incongruity",
    "osint_financial": "silver_financial_stress",
    "osint_darkweb":   "silver_darkweb_signals",
}


def run_domain(domain: str, dry_run: bool = False, env: str = "local",
               log_level: str = "INFO") -> dict:
    """
    Resolve and load a single Silver domain (internal or OSINT).
    Called by the Airflow DAG for each domain task running in parallel.
    Returns standard stage result dict.
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

    # Determine table name and execution mode
    if domain in _OSINT_TABLE_MAP:
        table_override, skip_truncate = _OSINT_TABLE_MAP[domain]
        parquet_name = _OSINT_PARQUET_NAME[domain]
        # Parquet reads from the actual Silver table (strip schema prefix)
        silver_tbl_short = table_override.split(".")[-1]
    else:
        table_override, skip_truncate = None, False
        parquet_name = f"sv_{domain}"
        silver_tbl_short = f"sv_{domain}"

    resolved_n, unresolved_n = _resolve_domain(
        env, domain, resolved_sql, unresolved_sql, dry_run,
        table_override=table_override, skip_truncate=skip_truncate,
    )
    total = resolved_n + unresolved_n
    _check_resolution_rate(domain, total, resolved_n)

    artifacts = []
    if not dry_run:
        df = _read_silver_table(env, silver_tbl_short)
        artifacts.append(_write_parquet(df, parquet_name, dry_run=False))

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

    Returns standard stage result dict.
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

        # Internal domain registry: name → (resolved_sql, unresolved_sql)
        internal_domains = {
            "hris":         _sql_hris(ingested_at),
            "pacs":         _sql_pacs(ingested_at),
            "network":      _sql_network(ingested_at),
            "dlp":          _sql_dlp(ingested_at),
            "comms":        _sql_comms(ingested_at),
            "pai":          _sql_pai(ingested_at),
            "geo":          _sql_geo(ingested_at),
            "adjudication": _sql_adjudication(ingested_at),
        }

        for domain, (resolved_sql, unresolved_sql) in internal_domains.items():
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

        # OSINT domain registry (run after internal, some depend on sv_hris)
        osint_domains = {
            "osint_twitter":   _sql_osint_twitter(ingested_at),
            "osint_instagram": _sql_osint_instagram(ingested_at),
            "osint_lifestyle": _sql_osint_lifestyle(ingested_at),
            "osint_financial": _sql_osint_financial(ingested_at),
            "osint_darkweb":   _sql_osint_darkweb(ingested_at),
        }

        for domain, (resolved_sql, unresolved_sql) in osint_domains.items():
            logger.info("Resolving OSINT %s in GP...", domain)
            table_override, skip_truncate = _OSINT_TABLE_MAP[domain]
            parquet_name = _OSINT_PARQUET_NAME[domain]
            silver_tbl_short = table_override.split(".")[-1]

            resolved_n, unresolved_n = _resolve_domain(
                env, domain, resolved_sql, unresolved_sql, dry_run,
                table_override=table_override, skip_truncate=skip_truncate,
            )

            total = resolved_n + unresolved_n
            rows_in          += total
            rows_out         += resolved_n
            total_unresolved += unresolved_n

            _check_resolution_rate(domain, total, resolved_n)

            if not dry_run:
                df = _read_silver_table(env, silver_tbl_short)
                parquet_path = _write_parquet(df, parquet_name, dry_run=False)
            else:
                parquet_path = str(SILVER_DIR / f"{parquet_name}.parquet")
            artifacts.append(parquet_path)

        all_domains = list(internal_domains.keys()) + list(osint_domains.keys())
        _write_lineage_map(all_domains, dry_run)

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
