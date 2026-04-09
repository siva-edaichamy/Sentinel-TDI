"""
s3_score_gold.py — Feature derivation and MADlib anomaly scoring (Gold layer).

Reads from Silver Greenplum tables (or Parquet fallback), derives all 13
behavioral features per employee per 7-day rolling window, trains MADlib
k-means (k=5), scores every employee-window, and writes the Gold
employee_risk_features table + Parquet snapshot.

Feature grain: employee_id + window_end_date (7-day rolling)
Algorithm:     MADlib k-means — distance from centroid = anomaly_score
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from sklearn.cluster import KMeans as _SKLearnKMeans
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False

from db import get_connection

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

RANDOM_SEED      = int(os.getenv("RANDOM_SEED", 42))
TIMELINE_DAYS    = int(os.getenv("TIMELINE_DAYS", 90))
TIMELINE_START   = date.fromisoformat(os.getenv("TIMELINE_START_DATE", "2026-01-01"))
ROLLING_WINDOW   = int(os.getenv("ROLLING_WINDOW", 7))
GOLD_DIR         = _PROJECT_ROOT / "data" / "gold"
SILVER_SCHEMA    = "insider_threat_silver"
GOLD_SCHEMA      = "insider_threat_gold"
PIPELINE_VERSION = os.getenv("PIPELINE_VERSION", "s3_score_gold_v1")
KMEANS_K         = 5
KMEANS_MAX_ITER  = 20
KMEANS_TOLERANCE = 0.001

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _windows() -> list[date]:
    """All window_end_dates in the timeline (from day 6 onward)."""
    timeline_end = TIMELINE_START + timedelta(days=TIMELINE_DAYS - 1)
    first_window = TIMELINE_START + timedelta(days=ROLLING_WINDOW - 1)
    result = []
    d = first_window
    while d <= timeline_end:
        result.append(d)
        d += timedelta(days=1)
    return result


def _read_silver(table: str, env: str, cols: list[str] | None = None) -> pd.DataFrame:
    """Read a Silver table from Greenplum, or fall back to Parquet."""
    try:
        col_expr = ", ".join(cols) if cols else "*"
        with get_connection(env) as conn:
            return pd.read_sql(
                f"SELECT {col_expr} FROM {SILVER_SCHEMA}.{table}",
                conn,
            )
    except Exception as e:
        logger.warning("GP read failed for %s (%s), falling back to Parquet", table, e)
        parquet = _PROJECT_ROOT / "data" / "silver" / f"{table}.parquet"
        df = pq.read_table(parquet).to_pandas()
        return df[cols] if cols else df


def _safe_zscore(series: pd.Series) -> pd.Series:
    """Z-score within a group; returns 0 if std is 0."""
    std = series.std()
    if std == 0 or pd.isna(std):
        return pd.Series(0.0, index=series.index)
    return (series - series.mean()) / std


def _winsorize(series: pd.Series, lower: float = 0.01, upper: float = 0.99) -> pd.Series:
    lo = series.quantile(lower)
    hi = series.quantile(upper)
    return series.clip(lo, hi)


def _min_max_norm(series: pd.Series) -> pd.Series:
    lo, hi = series.min(), series.max()
    if hi == lo:
        return pd.Series(0.0, index=series.index)
    return (series - lo) / (hi - lo)


# ---------------------------------------------------------------------------
# Silver aggregation per (employee_id, window_end_date)
# ---------------------------------------------------------------------------

def _agg_pacs(env: str, windows: list[date], hris_peers: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate PACS events into per-employee per-window features:
      - badge_swipes_outlier     : z-score of swipe count vs role peer group
      - after_hours_pacs_score   : after-hours swipe fraction vs role baseline
    """
    logger.info("Aggregating PACS events...")
    df = _read_silver("sv_pacs", env, ["employee_id", "event_date", "after_hours_flag"])
    df["event_date"] = pd.to_datetime(df["event_date"]).dt.date
    df["after_hours_flag"] = df["after_hours_flag"].astype(bool)

    rows = []
    window_end_dates = windows
    # Build daily swipe counts
    daily = df.groupby(["employee_id", "event_date"]).agg(
        swipes=("after_hours_flag", "count"),
        ah_swipes=("after_hours_flag", "sum"),
    ).reset_index()

    for wed in window_end_dates:
        wstart = wed - timedelta(days=ROLLING_WINDOW - 1)
        mask = (daily["event_date"] >= wstart) & (daily["event_date"] <= wed)
        w = daily[mask].groupby("employee_id").agg(
            total_swipes=("swipes", "sum"),
            ah_swipes=("ah_swipes", "sum"),
        ).reset_index()
        w["window_end_date"] = wed
        rows.append(w)

    agg = pd.concat(rows, ignore_index=True)

    # Merge peer group
    agg = agg.merge(hris_peers[["employee_id", "role_peer_group"]], on="employee_id", how="left")

    # z-score of swipe count within peer group per window
    agg["badge_swipes_outlier"] = agg.groupby(["window_end_date", "role_peer_group"])[
        "total_swipes"
    ].transform(_safe_zscore)

    # After-hours fraction vs peer group baseline
    agg["emp_ah_frac"] = agg["ah_swipes"] / agg["total_swipes"].replace(0, np.nan)
    agg["peer_ah_baseline"] = agg.groupby(["window_end_date", "role_peer_group"])[
        "emp_ah_frac"
    ].transform("mean")
    agg["after_hours_pacs_score"] = (agg["emp_ah_frac"] - agg["peer_ah_baseline"]).fillna(0)

    return agg[["employee_id", "window_end_date", "badge_swipes_outlier", "after_hours_pacs_score"]]


def _agg_network(env: str, windows: list[date], hris_peers: pd.DataFrame) -> pd.DataFrame:
    logger.info("Aggregating network events...")
    df = _read_silver("sv_network", env,
                      ["employee_id", "event_date", "after_hours_flag", "vpn_flag", "event_type"])
    df["event_date"] = pd.to_datetime(df["event_date"]).dt.date
    df["after_hours_flag"] = df["after_hours_flag"].astype(bool)
    df["vpn_flag"] = df["vpn_flag"].astype(bool)

    daily = df.groupby(["employee_id", "event_date"]).agg(
        events=("event_type", "count"),
        ah_events=("after_hours_flag", "sum"),
        vpn_events=("vpn_flag", "sum"),
    ).reset_index()

    rows = []
    for wed in windows:
        wstart = wed - timedelta(days=ROLLING_WINDOW - 1)
        mask = (daily["event_date"] >= wstart) & (daily["event_date"] <= wed)
        w = daily[mask].groupby("employee_id").agg(
            total_events=("events", "sum"),
            ah_events=("ah_events", "sum"),
            vpn_events=("vpn_events", "sum"),
        ).reset_index()
        w["window_end_date"] = wed
        rows.append(w)

    agg = pd.concat(rows, ignore_index=True)
    agg = agg.merge(hris_peers[["employee_id", "role_peer_group"]], on="employee_id", how="left")

    # After-hours network fraction vs peer baseline
    agg["ah_frac"] = agg["ah_events"] / agg["total_events"].replace(0, np.nan)
    agg["peer_ah_baseline"] = agg.groupby(["window_end_date", "role_peer_group"])[
        "ah_frac"
    ].transform("mean")
    agg["after_hours_network_score"] = (agg["ah_frac"] - agg["peer_ah_baseline"]).fillna(0)

    # VPN anomaly: z-score of VPN event count within peer group
    agg["vpn_anomaly_score"] = agg.groupby(["window_end_date", "role_peer_group"])[
        "vpn_events"
    ].transform(_safe_zscore)

    return agg[["employee_id", "window_end_date", "after_hours_network_score", "vpn_anomaly_score"]]


def _agg_dlp(env: str, windows: list[date], hris_peers: pd.DataFrame) -> pd.DataFrame:
    logger.info("Aggregating DLP events...")
    df = _read_silver("sv_dlp", env,
                      ["employee_id", "event_date", "usb_flag", "cloud_upload_flag", "file_size_mb"])
    df["event_date"] = pd.to_datetime(df["event_date"]).dt.date
    df["usb_flag"] = df["usb_flag"].astype(bool)
    df["cloud_upload_flag"] = df["cloud_upload_flag"].astype(bool)
    df["file_size_mb"] = pd.to_numeric(df["file_size_mb"], errors="coerce").fillna(0)

    daily = df.groupby(["employee_id", "event_date"]).agg(
        file_moves=("file_size_mb", "count"),
        usb_writes=("usb_flag", "sum"),
        cloud_uploads=("cloud_upload_flag", "sum"),
        total_mb=("file_size_mb", "sum"),
    ).reset_index()

    rows = []
    for wed in windows:
        wstart = wed - timedelta(days=ROLLING_WINDOW - 1)
        mask = (daily["event_date"] >= wstart) & (daily["event_date"] <= wed)
        w = daily[mask].groupby("employee_id").agg(
            file_moves=("file_moves", "sum"),
            usb_writes=("usb_writes", "sum"),
            cloud_uploads=("cloud_uploads", "sum"),
            total_mb=("total_mb", "sum"),
        ).reset_index()
        w["window_end_date"] = wed
        rows.append(w)

    agg = pd.concat(rows, ignore_index=True)
    agg = agg.merge(hris_peers[["employee_id", "role_peer_group"]], on="employee_id", how="left")

    # USB exfiltration: z-score vs 30-day personal baseline approximated by peer group baseline
    agg["usb_exfiltration_score"] = agg.groupby(["window_end_date", "role_peer_group"])[
        "usb_writes"
    ].transform(_safe_zscore)

    # File movement outlier: z-score vs peer group
    agg["file_movement_outlier"] = agg.groupby(["window_end_date", "role_peer_group"])[
        "file_moves"
    ].transform(_safe_zscore)

    # Cloud upload outlier: z-score vs peer group
    agg["cloud_upload_outlier"] = agg.groupby(["window_end_date", "role_peer_group"])[
        "cloud_uploads"
    ].transform(_safe_zscore)

    return agg[["employee_id", "window_end_date",
                "usb_exfiltration_score", "file_movement_outlier", "cloud_upload_outlier"]]


def _agg_comms(env: str, windows: list[date]) -> pd.DataFrame:
    logger.info("Aggregating comms events...")
    df = _read_silver("sv_comms", env,
                      ["employee_id", "event_date", "recipient_count", "external_recipient_flag"])
    df["event_date"] = pd.to_datetime(df["event_date"]).dt.date
    df["external_recipient_flag"] = df["external_recipient_flag"].astype(bool)
    df["recipient_count"] = pd.to_numeric(df["recipient_count"], errors="coerce").fillna(0)

    daily = df.groupby(["employee_id", "event_date"]).agg(
        messages=("recipient_count", "count"),
        ext_messages=("external_recipient_flag", "sum"),
        total_recipients=("recipient_count", "sum"),
    ).reset_index()

    rows = []
    for wed in windows:
        wstart = wed - timedelta(days=ROLLING_WINDOW - 1)
        prev_start = wstart - timedelta(days=ROLLING_WINDOW)
        prev_end = wstart - timedelta(days=1)

        curr_mask = (daily["event_date"] >= wstart) & (daily["event_date"] <= wed)
        prev_mask = (daily["event_date"] >= prev_start) & (daily["event_date"] <= prev_end)

        curr = daily[curr_mask].groupby("employee_id").agg(
            curr_msgs=("messages", "sum"),
            curr_ext=("ext_messages", "sum"),
            curr_recip=("total_recipients", "sum"),
        ).reset_index()
        prev = daily[prev_mask].groupby("employee_id").agg(
            prev_msgs=("messages", "sum"),
        ).reset_index()

        merged = curr.merge(prev, on="employee_id", how="left")
        merged["comms_volume_delta"] = (
            (merged["curr_msgs"] - merged["prev_msgs"].fillna(merged["curr_msgs"])) /
            merged["prev_msgs"].replace(0, np.nan).fillna(1)
        ).fillna(0)
        merged["external_comms_ratio"] = (
            merged["curr_ext"] / merged["curr_msgs"].replace(0, np.nan)
        ).fillna(0)
        merged["window_end_date"] = wed
        rows.append(merged[["employee_id", "window_end_date", "comms_volume_delta", "external_comms_ratio"]])

    return pd.concat(rows, ignore_index=True)


def _agg_pai(env: str, windows: list[date]) -> pd.DataFrame:
    logger.info("Aggregating PAI events...")
    df = _read_silver("sv_pai", env, ["employee_id", "event_date", "sentiment_score"])
    df["event_date"] = pd.to_datetime(df["event_date"]).dt.date
    df["sentiment_score"] = pd.to_numeric(df["sentiment_score"], errors="coerce")

    rows = []
    for wed in windows:
        wstart = wed - timedelta(days=ROLLING_WINDOW - 1)
        baseline_start = wed - timedelta(days=30)

        curr_mask = (df["event_date"] >= wstart) & (df["event_date"] <= wed)
        base_mask = (df["event_date"] >= baseline_start) & (df["event_date"] <= wed)

        curr = df[curr_mask].groupby("employee_id")["sentiment_score"].mean().reset_index()
        curr.columns = ["employee_id", "curr_sentiment"]
        base = df[base_mask].groupby("employee_id")["sentiment_score"].mean().reset_index()
        base.columns = ["employee_id", "base_sentiment"]

        merged = curr.merge(base, on="employee_id", how="left")
        merged["sentiment_trend"] = (merged["curr_sentiment"] - merged["base_sentiment"]).fillna(0)
        merged["window_end_date"] = wed
        rows.append(merged[["employee_id", "window_end_date", "sentiment_trend"]])

    return pd.concat(rows, ignore_index=True)


def _agg_geo(env: str, windows: list[date]) -> pd.DataFrame:
    """Detect impossible travel: two locations in the same day that are geographically impossible."""
    logger.info("Aggregating GEO events (impossible travel)...")
    df = _read_silver("sv_geo", env, ["employee_id", "event_date", "latitude", "longitude"])
    df["event_date"] = pd.to_datetime(df["event_date"]).dt.date
    df["latitude"]  = pd.to_numeric(df["latitude"], errors="coerce")
    df["longitude"] = pd.to_numeric(df["longitude"], errors="coerce")

    # Distance between two lat/lon points (haversine approximation in km)
    def _haversine_max(grp: pd.DataFrame) -> float:
        lats = grp["latitude"].dropna().values
        lons = grp["longitude"].dropna().values
        if len(lats) < 2:
            return 0.0
        max_dist = 0.0
        for i in range(len(lats)):
            for j in range(i + 1, len(lats)):
                dlat = np.radians(lats[j] - lats[i])
                dlon = np.radians(lons[j] - lons[i])
                a = np.sin(dlat/2)**2 + np.cos(np.radians(lats[i])) * np.cos(np.radians(lats[j])) * np.sin(dlon/2)**2
                dist = 6371 * 2 * np.arcsin(np.sqrt(a))
                max_dist = max(max_dist, dist)
        return max_dist

    # Flag days where max single-day distance > 500 km (impossible within hours)
    daily_max_dist = df.groupby(["employee_id", "event_date"]).apply(_haversine_max).reset_index()
    daily_max_dist.columns = ["employee_id", "event_date", "max_dist_km"]
    daily_max_dist["impossible"] = daily_max_dist["max_dist_km"] > 500

    rows = []
    for wed in windows:
        wstart = wed - timedelta(days=ROLLING_WINDOW - 1)
        mask = (daily_max_dist["event_date"] >= wstart) & (daily_max_dist["event_date"] <= wed)
        w = daily_max_dist[mask].groupby("employee_id")["impossible"].any().reset_index()
        w.columns = ["employee_id", "impossible_travel_flag"]
        w["window_end_date"] = wed
        rows.append(w)

    return pd.concat(rows, ignore_index=True)


def _agg_adjudication(env: str, windows: list[date]) -> pd.DataFrame:
    logger.info("Aggregating adjudication events...")
    df = _read_silver("sv_adjudication", env,
                      ["employee_id", "event_date", "investigation_flag", "status_change_flag"])
    df["event_date"] = pd.to_datetime(df["event_date"]).dt.date
    df["investigation_flag"]  = df["investigation_flag"].astype(bool)
    df["status_change_flag"]  = df["status_change_flag"].astype(bool)
    df["clearance_anomaly"]   = df["investigation_flag"] | df["status_change_flag"]

    rows = []
    for wed in windows:
        wstart = wed - timedelta(days=ROLLING_WINDOW - 1)
        mask = (df["event_date"] >= wstart) & (df["event_date"] <= wed)
        w = df[mask].groupby("employee_id")["clearance_anomaly"].any().reset_index()
        w.columns = ["employee_id", "clearance_anomaly_flag"]
        w["window_end_date"] = wed
        rows.append(w)

    return pd.concat(rows, ignore_index=True)


# ---------------------------------------------------------------------------
# Cross-domain anomaly count
# ---------------------------------------------------------------------------

def _compute_cross_domain_count(features: pd.DataFrame) -> pd.Series:
    """
    Count how many domains show an outlier signal in this window.
    Threshold: absolute z-score > 1.5 for continuous features, True for flags.
    """
    continuous = [
        "badge_swipes_outlier", "after_hours_pacs_score", "after_hours_network_score",
        "usb_exfiltration_score", "file_movement_outlier", "cloud_upload_outlier",
        "vpn_anomaly_score", "comms_volume_delta", "external_comms_ratio", "sentiment_trend",
    ]
    flags = ["impossible_travel_flag", "clearance_anomaly_flag"]

    count = pd.Series(0, index=features.index)
    for col in continuous:
        if col in features.columns:
            count += (features[col].abs().fillna(0) > 1.5).astype(int)
    for col in flags:
        if col in features.columns:
            count += features[col].fillna(False).astype(int)
    return count


# ---------------------------------------------------------------------------
# MADlib k-means via SQL
# ---------------------------------------------------------------------------

def _madlib_train_and_score(features: pd.DataFrame, env: str, model_run_id: str) -> pd.DataFrame:
    """
    Write feature vectors to Greenplum, run MADlib k-means, read back scores.
    Returns features DataFrame enriched with cluster_id and anomaly_score.
    """
    logger.info("Running MADlib k-means (k=%d)...", KMEANS_K)

    feature_cols = [
        "badge_swipes_outlier", "after_hours_pacs_score", "after_hours_network_score",
        "usb_exfiltration_score", "file_movement_outlier", "vpn_anomaly_score",
        "comms_volume_delta", "sentiment_trend", "cross_domain_anomaly_count",
    ]

    # Normalize feature vectors (min-max per feature across all windows)
    norm = features[feature_cols].copy()
    for col in feature_cols:
        norm[col] = _min_max_norm(_winsorize(norm[col].fillna(0)))

    features = features.copy()
    features["feature_vector"] = norm.apply(lambda r: list(r), axis=1)

    with get_connection(env) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # Clear and reload feature input table
            cur.execute(f"TRUNCATE {GOLD_SCHEMA}.employee_features")

            # Bulk insert feature vectors
            insert_sql = f"""
                INSERT INTO {GOLD_SCHEMA}.employee_features
                    (employee_id, window_end_date, feature_vector)
                VALUES (%s, %s, %s)
            """
            rows = [
                (row["employee_id"], row["window_end_date"], row["feature_vector"])
                for _, row in features.iterrows()
            ]
            cur.executemany(insert_sql, rows)
            logger.info("Loaded %d feature vectors into employee_features", len(rows))

            # Drop any prior MADlib result tables
            for t in ["kmeans_result", "kmeans_centroids"]:
                cur.execute(f"DROP TABLE IF EXISTS {GOLD_SCHEMA}.{t}")

            # Train k-means — MADlib 2.2.0: kmeanspp() stored via CREATE TABLE AS
            cur.execute(f"""
                CREATE TABLE {GOLD_SCHEMA}.gd_kmeans_output
                WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
                AS
                SELECT * FROM madlib.kmeanspp(
                    '{GOLD_SCHEMA}.employee_features',
                    'feature_vector',
                    {KMEANS_K},
                    'madlib.squared_dist_norm2',
                    'madlib.avg',
                    {KMEANS_MAX_ITER},
                    {KMEANS_TOLERANCE}::float8
                )
                DISTRIBUTED RANDOMLY
            """)
            kmeans_result = cur.fetchone()
            logger.info("MADlib k-means complete: %s", kmeans_result)

            # Score: assign each point to nearest centroid, compute distance
            cur.execute(f"""
                CREATE TABLE {GOLD_SCHEMA}.kmeans_result AS
                SELECT
                    ef.employee_id,
                    ef.window_end_date,
                    (madlib.closest_column(centroids, ef.feature_vector, 'madlib.squared_dist_norm2')).column_id AS cluster_id,
                    sqrt((madlib.closest_column(centroids, ef.feature_vector, 'madlib.squared_dist_norm2')).distance) AS anomaly_score
                FROM {GOLD_SCHEMA}.employee_features ef,
                     (SELECT output_table FROM madlib.kmeans_result LIMIT 1) kr,
                     (SELECT * FROM madlib.kmeans_result LIMIT 1) kmd
                CROSS JOIN LATERAL (
                    SELECT array_agg(centroid ORDER BY centroid_id) AS centroids
                    FROM (SELECT * FROM madlib.kmeans_result LIMIT 1) t,
                         LATERAL unnest(t.centroids) WITH ORDINALITY AS c(centroid, centroid_id)
                ) cent
                WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
                DISTRIBUTED BY (employee_id)
            """)

    # Read scores back
    with get_connection(env) as conn:
        scores = pd.read_sql(
            f"SELECT employee_id, window_end_date, cluster_id, anomaly_score FROM {GOLD_SCHEMA}.kmeans_result",
            conn,
        )

    features = features.merge(scores, on=["employee_id", "window_end_date"], how="left")
    return features


def _madlib_score_pure_sql(env: str, model_run_id: str) -> pd.DataFrame:
    """
    Full MADlib flow entirely in SQL, reading results back as a DataFrame.
    Used when the Python-side approach runs into MADlib API subtleties.
    """
    logger.info("Running MADlib k-means entirely via SQL...")
    with get_connection(env) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # Drop prior results
            for t in ["gd_kmeans_output", "gd_kmeans_centroids", "gd_scored"]:
                cur.execute(f"DROP TABLE IF EXISTS {GOLD_SCHEMA}.{t}")

            # Train — MADlib 2.2.0: kmeanspp() stored via CREATE TABLE AS
            cur.execute(f"""
                CREATE TABLE {GOLD_SCHEMA}.gd_kmeans_output
                WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
                AS
                SELECT * FROM madlib.kmeanspp(
                    '{GOLD_SCHEMA}.employee_features',
                    'feature_vector',
                    {KMEANS_K},
                    'madlib.squared_dist_norm2',
                    'madlib.avg',
                    {KMEANS_MAX_ITER},
                    {KMEANS_TOLERANCE}::float8
                )
                DISTRIBUTED RANDOMLY
            """)

            # Assign clusters and compute distance
            cur.execute(f"""
                CREATE TABLE {GOLD_SCHEMA}.gd_scored
                WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
                AS
                SELECT
                    ef.employee_id,
                    ef.window_end_date,
                    (madlib.closest_column(
                        km.centroids, ef.feature_vector, 'madlib.squared_dist_norm2'
                    )).column_id  AS cluster_id,
                    sqrt((madlib.closest_column(
                        km.centroids, ef.feature_vector, 'madlib.squared_dist_norm2'
                    )).distance)  AS anomaly_score
                FROM {GOLD_SCHEMA}.employee_features ef
                CROSS JOIN {GOLD_SCHEMA}.gd_kmeans_output km
                DISTRIBUTED BY (employee_id)
            """)

    with get_connection(env) as conn:
        return pd.read_sql(
            f"SELECT employee_id, window_end_date, cluster_id, anomaly_score FROM {GOLD_SCHEMA}.gd_scored",
            conn,
        )


# ---------------------------------------------------------------------------
# Write Gold output
# ---------------------------------------------------------------------------

def _load_gold(df: pd.DataFrame, env: str) -> int:
    """
    Load Gold records into employee_risk_features.
    APPENDOPTIMIZED tables don't support ON CONFLICT — use TRUNCATE + INSERT.
    """
    if df.empty:
        return 0

    gold_cols = [
        "employee_id", "window_end_date", "window_start_date",
        "badge_swipes_outlier", "after_hours_pacs_score", "after_hours_network_score",
        "usb_exfiltration_score", "file_movement_outlier", "cloud_upload_outlier",
        "vpn_anomaly_score", "impossible_travel_flag", "comms_volume_delta",
        "external_comms_ratio", "sentiment_trend", "clearance_anomaly_flag",
        "cross_domain_anomaly_count", "feature_vector",
        "cluster_id", "anomaly_score", "anomaly_percentile", "anomaly_tier",
        "source_silver_files", "model_run_id", "scored_at",
    ]
    available = [c for c in gold_cols if c in df.columns]
    insert_df = df[available].copy()

    for col in ["feature_vector", "source_silver_files"]:
        if col in insert_df.columns:
            insert_df[col] = insert_df[col].apply(
                lambda v: list(v) if isinstance(v, (list, np.ndarray)) else v
            )

    insert_df = insert_df.where(pd.notnull(insert_df), None)

    cols = list(insert_df.columns)
    records = [tuple(row) for row in insert_df.itertuples(index=False, name=None)]

    import psycopg2.extras
    with get_connection(env) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f"TRUNCATE {GOLD_SCHEMA}.employee_risk_features")
            psycopg2.extras.execute_values(
                cur,
                f"INSERT INTO {GOLD_SCHEMA}.employee_risk_features ({', '.join(cols)}) VALUES %s",
                records,
                page_size=500,
            )
    logger.info("Loaded %d rows into %s.employee_risk_features", len(records), GOLD_SCHEMA)
    return len(records)


# ---------------------------------------------------------------------------
# OSINT Gold stream scoring — 5 weekly risk tables + composite fusion
# ---------------------------------------------------------------------------

def _score_osint_streams(env: str, dry_run: bool, model_run_id: str) -> list[str]:
    """
    Score all 5 OSINT streams into Gold weekly risk tables and compute the
    composite risk fusion (gold_composite_risk).

    Weights (per CLAUDE.md):
      internal_behavioral=0.25, financial=0.18, twitter=0.15,
      lifestyle=0.15, darkweb=0.15, location=0.12

    Returns list of Gold table names populated.
    """
    if dry_run:
        logger.info("[DRY-RUN] Skipping OSINT Gold stream scoring")
        return []

    G = GOLD_SCHEMA
    S = SILVER_SCHEMA

    # ---- 1. gold_twitter_risk (from sv_pai) ----
    twitter_sql = f"""
        TRUNCATE {G}.gold_twitter_risk;

        INSERT INTO {G}.gold_twitter_risk (
            week_start_date, employee_id,
            sentiment_trend, sentiment_risk_score,
            primary_emotion, risk_narrative, scored_at
        )
        WITH weekly_sentiment AS (
            SELECT
                DATE_TRUNC('week', event_date)::DATE        AS week_start_date,
                employee_id,
                AVG(sentiment_score)                        AS week_avg,
                COUNT(*)                                    AS post_count
            FROM {S}.sv_pai
            GROUP BY DATE_TRUNC('week', event_date)::DATE, employee_id
        ),
        rolling_base AS (
            SELECT
                week_start_date, employee_id, week_avg, post_count,
                AVG(week_avg) OVER (
                    PARTITION BY employee_id
                    ORDER BY week_start_date
                    ROWS BETWEEN 4 PRECEDING AND CURRENT ROW
                ) AS rolling_30d_avg
            FROM weekly_sentiment
        ),
        emotion_weekly AS (
            SELECT
                DATE_TRUNC('week', event_date)::DATE        AS week_start_date,
                employee_id,
                unnest(emotion_tags)                        AS emotion
            FROM {S}.sv_pai
            WHERE emotion_tags IS NOT NULL
        ),
        top_emotion AS (
            SELECT week_start_date, employee_id, emotion,
                   ROW_NUMBER() OVER (
                       PARTITION BY week_start_date, employee_id
                       ORDER BY COUNT(*) DESC
                   ) AS rn
            FROM emotion_weekly
            GROUP BY week_start_date, employee_id, emotion
        )
        SELECT
            rb.week_start_date,
            rb.employee_id,
            CASE
                WHEN rb.week_avg < rb.rolling_30d_avg - 0.25 THEN 'declining_sharply'
                WHEN rb.week_avg < rb.rolling_30d_avg - 0.08 THEN 'declining'
                WHEN rb.week_avg > rb.rolling_30d_avg + 0.08 THEN 'improving'
                ELSE                                               'stable'
            END                                                 AS sentiment_trend,
            GREATEST(0.0, LEAST(1.0,
                (rb.rolling_30d_avg - rb.week_avg + 1.0) / 2.0
            ))                                                  AS sentiment_risk_score,
            te.emotion                                          AS primary_emotion,
            'Weekly sentiment avg=' || ROUND(rb.week_avg::NUMERIC,3)
                || ' vs 30d baseline=' || ROUND(rb.rolling_30d_avg::NUMERIC,3) AS risk_narrative,
            NOW()                                               AS scored_at
        FROM rolling_base rb
        LEFT JOIN top_emotion te
            ON rb.week_start_date = te.week_start_date
           AND rb.employee_id    = te.employee_id
           AND te.rn = 1
    """

    # ---- 2. gold_location_risk (from silver_geo_anomalies) ----
    location_sql = f"""
        TRUNCATE {G}.gold_location_risk;

        INSERT INTO {G}.gold_location_risk (
            week_start_date, employee_id,
            sensitive_location_count, work_hours_absence_count,
            location_risk_score, risk_narrative, scored_at
        )
        SELECT
            DATE_TRUNC('week', event_date)::DATE                AS week_start_date,
            employee_id,
            SUM(CASE WHEN anomaly_flag      THEN 1 ELSE 0 END)  AS sensitive_location_count,
            SUM(CASE WHEN work_hours_flag   THEN 1 ELSE 0 END)  AS work_hours_absence_count,
            LEAST(1.0,
                (SUM(CASE WHEN anomaly_flag THEN 1 ELSE 0 END) * 0.15)
                + (SUM(CASE WHEN incongruity_flag THEN 1 ELSE 0 END) * 0.10)
            )                                                   AS location_risk_score,
            'Anomaly locations=' || SUM(CASE WHEN anomaly_flag THEN 1 ELSE 0 END)
                || ' incongruent=' || SUM(CASE WHEN incongruity_flag THEN 1 ELSE 0 END) AS risk_narrative,
            NOW()                                               AS scored_at
        FROM {S}.silver_geo_anomalies
        GROUP BY DATE_TRUNC('week', event_date)::DATE, employee_id
    """

    # ---- 3. gold_lifestyle_risk (from silver_lifestyle_incongruity) ----
    lifestyle_sql = f"""
        TRUNCATE {G}.gold_lifestyle_risk;

        INSERT INTO {G}.gold_lifestyle_risk (
            week_start_date, employee_id,
            incongruity_event_count, cumulative_30day_spend,
            max_incongruity_score, lifestyle_risk_score,
            risk_narrative, scored_at
        )
        SELECT
            DATE_TRUNC('week', event_date)::DATE                AS week_start_date,
            employee_id,
            COUNT(*)                                            AS incongruity_event_count,
            MAX(cumulative_30day_spend)                         AS cumulative_30day_spend,
            MAX(incongruity_score)                              AS max_incongruity_score,
            LEAST(1.0,
                (COUNT(*) * 0.05) + (MAX(incongruity_score) * 0.30)
            )                                                   AS lifestyle_risk_score,
            'Events=' || COUNT(*) || ' max_incongruity=' || ROUND(MAX(incongruity_score)::NUMERIC,3)
                || ' 30d_spend=$' || MAX(cumulative_30day_spend) AS risk_narrative,
            NOW()                                               AS scored_at
        FROM {S}.silver_lifestyle_incongruity
        GROUP BY DATE_TRUNC('week', event_date)::DATE, employee_id
    """

    # ---- 4. gold_financial_stress_risk (from silver_financial_stress) ----
    financial_sql = f"""
        TRUNCATE {G}.gold_financial_stress_risk;

        INSERT INTO {G}.gold_financial_stress_risk (
            week_start_date, employee_id,
            active_record_count, cumulative_stress_score,
            financial_risk_score, risk_narrative, scored_at
        )
        SELECT
            DATE_TRUNC('week', event_date)::DATE                AS week_start_date,
            employee_id,
            COUNT(*)                                            AS active_record_count,
            MAX(cumulative_stress_score)                        AS cumulative_stress_score,
            LEAST(1.0,
                (COUNT(*) * 0.10) + (MAX(cumulative_stress_score) * 0.15)
            )                                                   AS financial_risk_score,
            'Public records=' || COUNT(*) || ' cumulative_stress='
                || ROUND(MAX(cumulative_stress_score)::NUMERIC,3)  AS risk_narrative,
            NOW()                                               AS scored_at
        FROM {S}.silver_financial_stress
        GROUP BY DATE_TRUNC('week', event_date)::DATE, employee_id
    """

    # ---- 5. gold_darkweb_risk (from silver_darkweb_signals) ----
    darkweb_sql = f"""
        TRUNCATE {G}.gold_darkweb_risk;

        INSERT INTO {G}.gold_darkweb_risk (
            week_start_date, employee_id,
            detection_count, max_severity,
            darkweb_risk_score, risk_narrative, scored_at
        )
        SELECT
            DATE_TRUNC('week', event_date)::DATE                AS week_start_date,
            employee_id,
            COUNT(*)                                            AS detection_count,
            MAX(CASE severity
                WHEN 'high'   THEN 1.0
                WHEN 'medium' THEN 0.5
                ELSE               0.2
            END)                                                AS max_severity,
            LEAST(1.0,
                (COUNT(*) * 0.15) + MAX(CASE severity
                    WHEN 'high'   THEN 0.60
                    WHEN 'medium' THEN 0.30
                    ELSE               0.10
                END)
            )                                                   AS darkweb_risk_score,
            'Detections=' || COUNT(*) || ' max_severity=' || MAX(severity) AS risk_narrative,
            NOW()                                               AS scored_at
        FROM {S}.silver_darkweb_signals
        GROUP BY DATE_TRUNC('week', event_date)::DATE, employee_id
    """

    # ---- 6. gold_composite_risk — fusion of all 6 streams ----
    # internal_behavioral_risk_score sourced from employee_risk_features (anomaly_percentile/100)
    composite_sql = f"""
        TRUNCATE {G}.gold_composite_risk;

        INSERT INTO {G}.gold_composite_risk (
            week_start_date, employee_id,
            twitter_risk_score, location_risk_score, lifestyle_risk_score,
            financial_risk_score, darkweb_risk_score,
            internal_behavioral_risk_score, composite_risk_score,
            risk_tier, tier_change_flag, primary_signal_driver,
            recommended_action, composite_narrative, scored_at
        )
        WITH internal_scores AS (
            SELECT
                (window_end_date - INTERVAL '6 days')::DATE     AS week_start_date,
                employee_id,
                AVG(anomaly_percentile / 100.0)                 AS internal_behavioral_risk_score
            FROM {G}.employee_risk_features
            GROUP BY (window_end_date - INTERVAL '6 days')::DATE, employee_id
        ),
        all_scores AS (
            SELECT
                COALESCE(
                    i.week_start_date, tw.week_start_date, lo.week_start_date,
                    ls.week_start_date, fi.week_start_date, dw.week_start_date
                )                                               AS week_start_date,
                COALESCE(
                    i.employee_id, tw.employee_id, lo.employee_id,
                    ls.employee_id, fi.employee_id, dw.employee_id
                )                                               AS employee_id,
                COALESCE(tw.sentiment_risk_score,    0.0)       AS twitter_risk_score,
                COALESCE(lo.location_risk_score,     0.0)       AS location_risk_score,
                COALESCE(ls.lifestyle_risk_score,    0.0)       AS lifestyle_risk_score,
                COALESCE(fi.financial_risk_score,    0.0)       AS financial_risk_score,
                COALESCE(dw.darkweb_risk_score,      0.0)       AS darkweb_risk_score,
                COALESCE(i.internal_behavioral_risk_score, 0.0) AS internal_behavioral_risk_score
            FROM internal_scores i
            FULL OUTER JOIN {G}.gold_twitter_risk   tw USING (week_start_date, employee_id)
            FULL OUTER JOIN {G}.gold_location_risk  lo USING (week_start_date, employee_id)
            FULL OUTER JOIN {G}.gold_lifestyle_risk ls USING (week_start_date, employee_id)
            FULL OUTER JOIN {G}.gold_financial_stress_risk fi USING (week_start_date, employee_id)
            FULL OUTER JOIN {G}.gold_darkweb_risk   dw USING (week_start_date, employee_id)
        ),
        scored AS (
            SELECT *,
                ROUND(CAST(
                    (internal_behavioral_risk_score * 0.25)
                  + (financial_risk_score           * 0.18)
                  + (twitter_risk_score             * 0.15)
                  + (lifestyle_risk_score           * 0.15)
                  + (darkweb_risk_score             * 0.15)
                  + (location_risk_score            * 0.12)
                AS NUMERIC), 4)                                 AS composite_risk_score,
                GREATEST(
                    internal_behavioral_risk_score,
                    financial_risk_score,
                    twitter_risk_score,
                    lifestyle_risk_score,
                    darkweb_risk_score,
                    location_risk_score
                )                                               AS max_stream_score,
                CASE
                    WHEN internal_behavioral_risk_score = GREATEST(
                        internal_behavioral_risk_score, financial_risk_score, twitter_risk_score,
                        lifestyle_risk_score, darkweb_risk_score, location_risk_score)
                        THEN 'internal_behavioral'
                    WHEN financial_risk_score = GREATEST(
                        internal_behavioral_risk_score, financial_risk_score, twitter_risk_score,
                        lifestyle_risk_score, darkweb_risk_score, location_risk_score)
                        THEN 'financial_stress'
                    WHEN darkweb_risk_score = GREATEST(
                        internal_behavioral_risk_score, financial_risk_score, twitter_risk_score,
                        lifestyle_risk_score, darkweb_risk_score, location_risk_score)
                        THEN 'dark_web'
                    WHEN lifestyle_risk_score = GREATEST(
                        internal_behavioral_risk_score, financial_risk_score, twitter_risk_score,
                        lifestyle_risk_score, darkweb_risk_score, location_risk_score)
                        THEN 'lifestyle'
                    WHEN twitter_risk_score = GREATEST(
                        internal_behavioral_risk_score, financial_risk_score, twitter_risk_score,
                        lifestyle_risk_score, darkweb_risk_score, location_risk_score)
                        THEN 'twitter_sentiment'
                    ELSE 'location'
                END                                             AS primary_signal_driver
            FROM all_scores
            WHERE week_start_date IS NOT NULL AND employee_id IS NOT NULL
        )
        SELECT
            s.week_start_date,
            s.employee_id,
            s.twitter_risk_score,
            s.location_risk_score,
            s.lifestyle_risk_score,
            s.financial_risk_score,
            s.darkweb_risk_score,
            s.internal_behavioral_risk_score,
            s.composite_risk_score,
            CASE
                WHEN s.composite_risk_score >= 0.75 THEN 'CRITICAL'
                WHEN s.composite_risk_score >= 0.50 THEN 'HIGH'
                WHEN s.composite_risk_score >= 0.25 THEN 'MEDIUM'
                ELSE                                     'LOW'
            END                                                 AS risk_tier,
            FALSE                                               AS tier_change_flag,
            s.primary_signal_driver,
            CASE
                WHEN s.composite_risk_score >= 0.75 THEN 'ESCALATE'
                WHEN s.composite_risk_score >= 0.50 THEN 'INVESTIGATE'
                WHEN s.composite_risk_score >= 0.25 THEN 'MONITOR'
                ELSE                                     'ROUTINE'
            END                                                 AS recommended_action,
            'Composite=' || s.composite_risk_score
                || ' driver=' || s.primary_signal_driver        AS composite_narrative,
            NOW()                                               AS scored_at
        FROM scored s
    """

    populated = []
    tables_sql = [
        ("gold_twitter_risk",         twitter_sql),
        ("gold_location_risk",        location_sql),
        ("gold_lifestyle_risk",       lifestyle_sql),
        ("gold_financial_stress_risk", financial_sql),
        ("gold_darkweb_risk",         darkweb_sql),
        ("gold_composite_risk",       composite_sql),
    ]

    with get_connection(env) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            for table_name, sql_block in tables_sql:
                logger.info("Scoring OSINT Gold: %s", table_name)
                for stmt in _split_sql(sql_block):
                    cur.execute(stmt)
                populated.append(f"{G}.{table_name}")
                logger.info("  %s loaded (rowcount=%s)", table_name, cur.rowcount)

    return populated


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(dry_run: bool = False, env: str = "local", log_level: str = "INFO") -> dict:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    t0 = time.perf_counter()
    model_run_id = str(uuid.uuid4())
    logger.info("s3_score_gold START | dry_run=%s env=%s model_run_id=%s", dry_run, env, model_run_id)

    artifacts: list[str] = []
    rows_out = 0

    try:
        windows = _windows()
        logger.info("Computing %d rolling windows...", len(windows))

        # Load HRIS peer group for z-score groupings
        hris_df = _read_silver("sv_hris", env, ["employee_id", "role_peer_group"])
        hris_peers = hris_df.drop_duplicates("employee_id")[["employee_id", "role_peer_group"]]

        # All active employee_ids
        all_employees = pd.DataFrame({"employee_id": hris_peers["employee_id"].unique()})

        # ---- Aggregate all domains ----
        pacs_agg  = _agg_pacs(env, windows, hris_peers)
        net_agg   = _agg_network(env, windows, hris_peers)
        dlp_agg   = _agg_dlp(env, windows, hris_peers)
        comms_agg = _agg_comms(env, windows)
        pai_agg   = _agg_pai(env, windows)
        geo_agg   = _agg_geo(env, windows)
        adj_agg   = _agg_adjudication(env, windows)

        # ---- Build full employee × window grid ----
        logger.info("Building employee x window grid...")
        window_df = pd.DataFrame({"window_end_date": windows})
        grid = all_employees.merge(window_df, how="cross")

        # ---- Join all aggregations ----
        logger.info("Joining feature aggregations...")
        features = grid.copy()
        for agg_df in [pacs_agg, net_agg, dlp_agg, comms_agg, pai_agg, geo_agg, adj_agg]:
            features = features.merge(agg_df, on=["employee_id", "window_end_date"], how="left")

        features["window_start_date"] = features["window_end_date"].apply(
            lambda d: d - timedelta(days=ROLLING_WINDOW - 1)
        )

        # Fill flags with False, numeric with 0
        flag_cols = ["impossible_travel_flag", "clearance_anomaly_flag"]
        for col in flag_cols:
            if col in features.columns:
                features[col] = features[col].fillna(False).astype(bool)

        num_cols = [
            "badge_swipes_outlier", "after_hours_pacs_score", "after_hours_network_score",
            "usb_exfiltration_score", "file_movement_outlier", "cloud_upload_outlier",
            "vpn_anomaly_score", "comms_volume_delta", "external_comms_ratio", "sentiment_trend",
        ]
        for col in num_cols:
            if col in features.columns:
                features[col] = features[col].fillna(0.0)

        # Cross-domain anomaly count
        features["cross_domain_anomaly_count"] = _compute_cross_domain_count(features).astype(int)

        logger.info("Feature grid: %d rows (employees=%d, windows=%d)",
                    len(features), len(all_employees), len(windows))

        # ---- Load feature vectors and run MADlib ----
        feature_cols = [
            "badge_swipes_outlier", "after_hours_pacs_score", "after_hours_network_score",
            "usb_exfiltration_score", "file_movement_outlier", "vpn_anomaly_score",
            "comms_volume_delta", "sentiment_trend", "cross_domain_anomaly_count",
        ]
        norm = features[feature_cols].copy()
        for col in feature_cols:
            norm[col] = _min_max_norm(_winsorize(norm[col].fillna(0)))
        features["feature_vector"] = norm.apply(lambda r: list(r.astype(float)), axis=1)

        if dry_run:
            logger.info("[DRY-RUN] Skipping scoring and Greenplum writes")
            features["cluster_id"]    = 0
            features["anomaly_score"] = 0.0
        else:
            # Build numpy feature matrix
            feat_matrix = np.array(features["feature_vector"].tolist(), dtype=float)

            if _madlib_accessible(env):
                logger.info("MADlib available — using GP in-database k-means")
                # Load feature vectors to GP
                with get_connection(env) as conn:
                    conn.autocommit = True
                    with conn.cursor() as cur:
                        cur.execute(f"TRUNCATE {GOLD_SCHEMA}.employee_features")
                        ins = [
                            (row["employee_id"], row["window_end_date"], row["feature_vector"])
                            for _, row in features.iterrows()
                        ]
                        import psycopg2.extras
                        psycopg2.extras.execute_values(
                            cur,
                            f"INSERT INTO {GOLD_SCHEMA}.employee_features "
                            f"(employee_id, window_end_date, feature_vector) VALUES %s",
                            ins,
                            page_size=500,
                        )
                        logger.info("Loaded %d feature vectors", len(ins))
                scores = _run_madlib_sql(env, model_run_id)
                features = features.merge(scores, on=["employee_id", "window_end_date"], how="left")
                features["cluster_id"]    = features["cluster_id"].fillna(0).astype(int)
                features["anomaly_score"] = features["anomaly_score"].fillna(0.0)
            else:
                logger.warning(
                    "MADlib not accessible for current user — falling back to sklearn KMeans. "
                    "Grant: GRANT USAGE ON SCHEMA madlib TO <your_gp_user>; to enable MADlib."
                )
                scores = _sklearn_kmeans(feat_matrix, features)
                features["cluster_id"]    = scores["cluster_id"].values
                features["anomaly_score"] = scores["anomaly_score"].values

        # ---- Percentile and tier ----
        features["anomaly_percentile"] = features["anomaly_score"].rank(pct=True) * 100
        features["anomaly_tier"] = pd.cut(
            features["anomaly_percentile"],
            bins=[0, 75, 95, 100],
            labels=["LOW", "MEDIUM", "HIGH"],
            right=True,
            include_lowest=True,
        ).astype(str)

        # ---- Lineage ----
        silver_files = [
            "sv_pacs", "sv_network", "sv_dlp", "sv_comms",
            "sv_pai", "sv_geo", "sv_adjudication",
        ]
        features["source_silver_files"] = [silver_files] * len(features)
        features["model_run_id"]        = model_run_id
        features["scored_at"]           = _now()

        rows_out = len(features)

        # ---- Write Parquet ----
        if not dry_run:
            GOLD_DIR.mkdir(parents=True, exist_ok=True)
            parquet_path = GOLD_DIR / "employee_risk_features.parquet"
            # Convert list columns to object for Parquet compatibility
            out_df = features.copy()
            out_df["feature_vector"]     = out_df["feature_vector"].apply(list)
            out_df["source_silver_files"] = out_df["source_silver_files"].apply(list)
            table = pa.Table.from_pandas(out_df, preserve_index=False)
            pq.write_table(table, parquet_path, compression="snappy")
            artifacts.append(str(parquet_path))
            logger.info("Wrote Gold Parquet: %s", parquet_path)

            # ---- Load Gold to Greenplum ----
            _load_gold(features, env)
            artifacts.append(f"{GOLD_SCHEMA}.employee_risk_features")
        else:
            artifacts.append("[DRY-RUN] data/gold/employee_risk_features.parquet")

        _write_feature_dict(dry_run)

        # ---- OSINT Gold stream scoring ----
        logger.info("Scoring OSINT Gold streams...")
        osint_gold_tables = _score_osint_streams(env, dry_run, model_run_id)
        artifacts.extend(osint_gold_tables)
        logger.info("OSINT Gold streams populated: %s", osint_gold_tables)

        duration = time.perf_counter() - t0
        logger.info("s3_score_gold DONE | rows_out=%d duration=%.2fs", rows_out, duration)

        return {
            "status": "success",
            "rows_in": rows_out,
            "rows_out": rows_out,
            "duration_seconds": round(duration, 3),
            "artifacts": artifacts,
        }

    except Exception as exc:
        duration = time.perf_counter() - t0
        logger.exception("s3_score_gold FAILED: %s", exc)
        return {
            "status": "failure",
            "rows_in": 0,
            "rows_out": 0,
            "duration_seconds": round(duration, 3),
            "artifacts": artifacts,
        }


# ---------------------------------------------------------------------------
# MADlib availability check
# ---------------------------------------------------------------------------

def _madlib_accessible(env: str) -> bool:
    """Return True if the current DB user can call madlib.kmeans."""
    try:
        with get_connection(env) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT madlib.version()")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# sklearn KMeans fallback (identical output schema to MADlib path)
# ---------------------------------------------------------------------------

def _sklearn_kmeans(feat_matrix: np.ndarray, features: pd.DataFrame) -> pd.DataFrame:
    """
    Run sklearn KMeans and return per-row cluster_id and anomaly_score.
    anomaly_score = Euclidean distance from assigned centroid (same semantics as MADlib).
    """
    km = _SKLearnKMeans(
        n_clusters=KMEANS_K,
        max_iter=KMEANS_MAX_ITER,
        tol=KMEANS_TOLERANCE,
        random_state=RANDOM_SEED,
        n_init=10,
    )
    km.fit(feat_matrix)
    labels     = km.labels_
    centroids  = km.cluster_centers_
    distances  = np.linalg.norm(feat_matrix - centroids[labels], axis=1)

    result = features[["employee_id", "window_end_date"]].copy()
    result["cluster_id"]    = labels.astype(int)
    result["anomaly_score"] = distances.astype(float)
    logger.info("sklearn KMeans done: k=%d inertia=%.4f", KMEANS_K, km.inertia_)
    return result


# ---------------------------------------------------------------------------
# MADlib SQL file execution
# ---------------------------------------------------------------------------

def _run_madlib_sql(env: str, model_run_id: str) -> pd.DataFrame:
    """Execute the MADlib SQL files and return scores as a DataFrame."""
    sql_dir = _PROJECT_ROOT / "sql"

    # Write the SQL files if not already done (s4 writes them formally)
    _ensure_madlib_sql(sql_dir, model_run_id)

    train_sql = (sql_dir / "madlib_train.sql").read_text()
    score_sql  = (sql_dir / "madlib_score.sql").read_text()

    with get_connection(env) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            logger.info("Executing MADlib train SQL...")
            for stmt in _split_sql(train_sql):
                cur.execute(stmt)
            logger.info("Executing MADlib score SQL...")
            for stmt in _split_sql(score_sql):
                cur.execute(stmt)

    with get_connection(env) as conn:
        return pd.read_sql(
            f"SELECT employee_id, window_end_date, cluster_id, anomaly_score "
            f"FROM {GOLD_SCHEMA}.gd_scored",
            conn,
        )


def _split_sql(sql_text: str) -> list[str]:
    """Split SQL on semicolons, ignoring semicolons inside -- comments."""
    stmts = []
    current: list[str] = []
    for line in sql_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            # Comment line — include as-is, never split on its content
            current.append(line)
        elif ";" in line:
            # Split at the semicolon; anything after it starts the next statement
            before, _, after = line.partition(";")
            current.append(before)
            body = " ".join(l for l in current if not l.strip().startswith("--")).strip()
            if body:
                stmts.append("\n".join(current).strip())
            current = [after] if after.strip() else []
        else:
            current.append(line)
    # Flush any trailing content
    if current:
        body = " ".join(l for l in current if not l.strip().startswith("--")).strip()
        if body:
            stmts.append("\n".join(current).strip())
    return stmts


def _ensure_madlib_sql(sql_dir: Path, model_run_id: str) -> None:
    """Write MADlib SQL files if they are still placeholders."""
    train_path = sql_dir / "madlib_train.sql"
    score_path = sql_dir / "madlib_score.sql"

    if "TODO" in train_path.read_text():
        train_path.write_text(f"""
-- madlib_train.sql — MADlib k-means training
-- model_run_id: {model_run_id}
-- MADlib 2.2.0: kmeanspp() returns a row with centroids — store via CREATE TABLE AS

-- Drop prior MADlib result tables
DROP TABLE IF EXISTS {GOLD_SCHEMA}.gd_kmeans_output;

-- Train k-means++ on normalized feature vectors (DISTRIBUTED after AS query in GP)
CREATE TABLE {GOLD_SCHEMA}.gd_kmeans_output
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
AS
SELECT * FROM madlib.kmeanspp(
    '{GOLD_SCHEMA}.employee_features',
    'feature_vector',
    {KMEANS_K},
    'madlib.squared_dist_norm2',
    'madlib.avg',
    {KMEANS_MAX_ITER},
    {KMEANS_TOLERANCE}::float8
)
DISTRIBUTED RANDOMLY;
""")

    if "TODO" in score_path.read_text():
        score_path.write_text(f"""
-- madlib_score.sql — Anomaly scoring and percentile ranking
-- Reads centroids from gd_kmeans_output, assigns clusters, computes distance

DROP TABLE IF EXISTS {GOLD_SCHEMA}.gd_scored;

-- WITH clause must appear before AS in GP CREATE TABLE AS
CREATE TABLE {GOLD_SCHEMA}.gd_scored
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
AS
SELECT
    ef.employee_id,
    ef.window_end_date,
    (madlib.closest_column(
        km.centroids, ef.feature_vector, 'madlib.squared_dist_norm2'
    )).column_id  AS cluster_id,
    sqrt((madlib.closest_column(
        km.centroids, ef.feature_vector, 'madlib.squared_dist_norm2'
    )).distance)  AS anomaly_score
FROM {GOLD_SCHEMA}.employee_features ef
CROSS JOIN {GOLD_SCHEMA}.gd_kmeans_output km
DISTRIBUTED BY (employee_id);
""")


# ---------------------------------------------------------------------------
# Feature dictionary schema doc
# ---------------------------------------------------------------------------

def _write_feature_dict(dry_run: bool) -> None:
    schema = {
        "generated_at": _now(),
        "grain": "employee_id + window_end_date (7-day rolling)",
        "algorithm": "MADlib k-means (k=5), distance from centroid = anomaly_score",
        "features": {
            "badge_swipes_outlier":      {"source": "sv_pacs",         "type": "float", "derivation": "z-score of 7d swipe count vs role peer group"},
            "after_hours_pacs_score":    {"source": "sv_pacs",         "type": "float", "derivation": "after-hours swipe fraction vs peer baseline"},
            "after_hours_network_score": {"source": "sv_network",      "type": "float", "derivation": "after-hours network fraction vs peer baseline"},
            "usb_exfiltration_score":    {"source": "sv_dlp",          "type": "float", "derivation": "z-score of USB write count vs peer group"},
            "file_movement_outlier":     {"source": "sv_dlp",          "type": "float", "derivation": "z-score of file move count vs peer group"},
            "cloud_upload_outlier":      {"source": "sv_dlp",          "type": "float", "derivation": "z-score of cloud upload count vs peer group"},
            "vpn_anomaly_score":         {"source": "sv_network",      "type": "float", "derivation": "z-score of VPN event count vs peer group"},
            "impossible_travel_flag":    {"source": "sv_geo",          "type": "bool",  "derivation": "two locations > 500km apart on same day"},
            "comms_volume_delta":        {"source": "sv_comms",        "type": "float", "derivation": "week-over-week message volume change ratio"},
            "external_comms_ratio":      {"source": "sv_comms",        "type": "float", "derivation": "external recipient fraction of total messages"},
            "sentiment_trend":           {"source": "sv_pai",          "type": "float", "derivation": "7d avg sentiment minus 30d personal baseline"},
            "clearance_anomaly_flag":    {"source": "sv_adjudication", "type": "bool",  "derivation": "any investigation or status change in window"},
            "cross_domain_anomaly_count": {"source": "all",            "type": "int",   "derivation": "count of domains with outlier signal in window"},
        },
        "output_columns": {
            "anomaly_score":      "Distance from k-means centroid (higher = more anomalous)",
            "anomaly_percentile": "Percentile rank 0-100 across all employee-windows",
            "anomaly_tier":       "HIGH (>95th pct) | MEDIUM (75-95th) | LOW (<75th)",
        },
    }
    path = _PROJECT_ROOT / "schema" / "feature_dictionary.json"
    if not dry_run:
        path.write_text(json.dumps(schema, indent=2))
    logger.info("Feature dictionary: %s", path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="s3_score_gold — feature derivation and MADlib scoring")
    p.add_argument("--dry-run",   action="store_true")
    p.add_argument("--env",       default="local", choices=["local", "dev", "prod"])
    p.add_argument("--log-level", default="INFO",  choices=["DEBUG", "INFO", "WARNING"])
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    result = run(dry_run=args.dry_run, env=args.env, log_level=args.log_level)
    print(json.dumps(result, indent=2, default=str))
