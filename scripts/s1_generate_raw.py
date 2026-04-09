"""
s1_generate_raw.py — Synthetic Bronze-layer data generation.

Generates all 8 event domains + 4 mapping tables for the insider threat demo.
Output: /data/bronze/*.csv  (all files CSV — compatible with GP S3 external tables)
Upload: sentinel-bronze/bronze/<filename>.csv on MinIO

Key design decisions:
- RANDOM_SEED=42 for full reproducibility
- ~25 employees have statistically separable behavior across multiple domains
  (elevated after-hours + unusual file movement + sentiment decline)
- No explicit threat labels or flags — MADlib finds the signal
- Realistic noise: missed badge swipes, shared workstations, VPN from home, travel days
- ~5% unmapped social handles for realism in identity resolution
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Ensure the scripts directory is on the path so generate_osint_streams is importable
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import generate_osint_streams

import numpy as np
import pandas as pd
import boto3
from botocore.client import Config
from dotenv import load_dotenv
from faker import Faker

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

RANDOM_SEED    = int(os.getenv("RANDOM_SEED", 42))
EMPLOYEE_COUNT = int(os.getenv("EMPLOYEE_COUNT", 500))
TIMELINE_DAYS  = int(os.getenv("TIMELINE_DAYS", 90))
TIMELINE_START = date.fromisoformat(os.getenv("TIMELINE_START_DATE", "2026-01-01"))
BRONZE_DIR     = _PROJECT_ROOT / "data" / "bronze"

# MinIO / S3 config
MINIO_ENDPOINT  = os.getenv("MINIO_ENDPOINT", "http://localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_BUCKET    = os.getenv("MINIO_BUCKET", "sentinel-bronze")
MINIO_REGION    = os.getenv("MINIO_REGION", "us-east-1")
MINIO_PREFIX    = "bronze"

# High-risk cohort size (statistically separable, no explicit label)
HIGH_RISK_N = 25

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_all(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    Faker.seed(seed)


def _ts(d: date, hour: int | None = None, minute: int | None = None) -> datetime:
    """Build a UTC-aware datetime from a date and optional hour/minute."""
    h = hour if hour is not None else random.randint(0, 23)
    m = minute if minute is not None else random.randint(0, 59)
    return datetime(d.year, d.month, d.day, h, m, random.randint(0, 59),
                    tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _sha256(obj: Any) -> str:
    raw = json.dumps(obj, default=str, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _timeline() -> list[date]:
    return [TIMELINE_START + timedelta(days=i) for i in range(TIMELINE_DAYS)]


def _is_after_hours(dt: datetime) -> bool:
    return dt.hour < 8 or dt.hour >= 18


def _is_weekend(d: date) -> bool:
    return d.weekday() >= 5


def _to_date(val: Any) -> date | None:
    """Safely convert a DataFrame cell value to date, returning None for NaN/None."""
    if val is None or (isinstance(val, float) and np.isnan(val)):
        return None
    if isinstance(val, date):
        return val
    return date.fromisoformat(str(val))


# ---------------------------------------------------------------------------
# Employee master
# ---------------------------------------------------------------------------

def _build_employee_master(fake: Faker) -> pd.DataFrame:
    """Generate 500 employees with realistic org structure."""
    rng = np.random.default_rng(RANDOM_SEED)

    departments = ["Engineering", "Finance", "Legal", "HR", "Operations",
                   "Sales", "IT Security", "Research", "Logistics", "Executive"]
    clearance_levels = ["UNCLASSIFIED", "SECRET", "TOP_SECRET"]
    clearance_weights = [0.50, 0.35, 0.15]

    # Designate high-risk cohort indices (deterministic from seed)
    high_risk_ids = set(rng.choice(EMPLOYEE_COUNT, size=HIGH_RISK_N, replace=False).tolist())

    rows = []
    for i in range(EMPLOYEE_COUNT):
        emp_id = f"EMP_{i+1:05d}"
        dept = departments[i % len(departments)]
        peer_group = f"{dept.replace(' ', '_').upper()}_L{(i % 3) + 1}"
        clearance = rng.choice(clearance_levels, p=clearance_weights)
        start_d = TIMELINE_START - timedelta(days=int(rng.integers(30, 1800)))
        # ~3% of employees terminate during the 90-day window
        terminated = (i % 33 == 0)
        end_d = (TIMELINE_START + timedelta(days=int(rng.integers(10, 80)))
                 if terminated else None)

        rows.append({
            "employee_id":    emp_id,
            "full_name":      fake.name(),
            "email_address":  f"{emp_id.lower()}@corp.internal",
            "slack_handle":   f"@{emp_id.lower()}",
            "badge_id":       f"BADGE_{i+1:05d}",
            "machine_id":     f"MACH_{i+1:05d}",
            "department":     dept,
            "role_title":     fake.job(),
            "role_peer_group": peer_group,
            "clearance_level": clearance,
            "employment_status": "terminated" if terminated else "active",
            "start_date":     start_d.isoformat(),
            "end_date":       end_d.isoformat() if end_d else None,
            "is_high_risk":   i in high_risk_ids,   # internal only — not written to any domain file
        })

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Mapping tables (Bronze artifacts for Silver identity resolution)
# ---------------------------------------------------------------------------

def _gen_badge_registry(employees: pd.DataFrame) -> pd.DataFrame:
    return employees[["badge_id", "employee_id", "start_date"]].rename(
        columns={"start_date": "issued_date"}
    ).copy()


def _gen_asset_assignment(employees: pd.DataFrame) -> pd.DataFrame:
    """Primary assignment per employee. ~10% of machines are shared (two employees)."""
    rng = np.random.default_rng(RANDOM_SEED + 1)
    rows = []
    for _, emp in employees.iterrows():
        rows.append({
            "machine_id":     emp["machine_id"],
            "employee_id":    emp["employee_id"],
            "effective_start": emp["start_date"],
            "effective_end":   emp["end_date"],
        })
    # Inject ~10% shared machines: a second employee previously used the same machine
    shared_idx = rng.choice(len(employees), size=int(EMPLOYEE_COUNT * 0.1), replace=False)
    for idx in shared_idx:
        emp = employees.iloc[idx]
        prev_end = (pd.Timestamp(emp["start_date"]) - timedelta(days=1)).date().isoformat()
        prev_start = (pd.Timestamp(emp["start_date"]) - timedelta(days=int(rng.integers(30, 180)))).date().isoformat()
        rows.append({
            "machine_id":     emp["machine_id"],
            "employee_id":    f"EMP_{(idx + 300) % EMPLOYEE_COUNT + 1:05d}",   # different employee
            "effective_start": prev_start,
            "effective_end":   prev_end,
        })
    return pd.DataFrame(rows)


def _gen_directory(employees: pd.DataFrame) -> pd.DataFrame:
    return employees[["email_address", "slack_handle", "employee_id"]].copy()


def _gen_social_handle_map(employees: pd.DataFrame, fake: Faker) -> pd.DataFrame:
    """Social handles — one per platform per employee, ~5% unmapped ghosts."""
    rng = np.random.default_rng(RANDOM_SEED + 2)
    rows = []
    platforms = ["twitter", "instagram", "linkedin"]
    for _, emp in employees.iterrows():
        # Each employee gets 1-3 platforms (always twitter, ~70% instagram, ~50% linkedin)
        emp_platforms = ["twitter"]
        if rng.random() < 0.70:
            emp_platforms.append("instagram")
        if rng.random() < 0.50:
            emp_platforms.append("linkedin")
        for platform in emp_platforms:
            rows.append({
                "social_handle": f"@{fake.user_name()}_{emp['employee_id'].lower()}_{platform[:2]}",
                "employee_id":   emp["employee_id"],
                "platform":      platform,
            })
    # Add ~5% ghost handles (no employee link)
    ghost_count = int(EMPLOYEE_COUNT * 0.05)
    for _ in range(ghost_count):
        platform = platforms[rng.integers(0, len(platforms))]
        rows.append({
            "social_handle": f"@{fake.user_name()}_{fake.lexify('????')}",
            "employee_id":   None,
            "platform":      platform,
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Domain event generators
# ---------------------------------------------------------------------------

def _gen_hris(employees: pd.DataFrame) -> pd.DataFrame:
    """HRIS — authoritative employee master. One record per employee."""
    cols = ["employee_id", "full_name", "department", "role_title",
            "role_peer_group", "clearance_level", "employment_status",
            "start_date", "end_date"]
    return employees[cols].copy()


def _gen_pacs(employees: pd.DataFrame, timeline: list[date]) -> list[dict]:
    """Physical access control — badge swipe events."""
    rng = np.random.default_rng(RANDOM_SEED + 10)
    records = []
    buildings = ["HQ-A", "HQ-B", "DATA-CENTER", "ANNEX-1"]
    doors = {b: [f"{b}-D{i:02d}" for i in range(1, 6)] for b in buildings}

    for _, emp in employees.iterrows():
        emp_id = emp["employee_id"]
        is_high_risk = emp["is_high_risk"]

        for d in timeline:
            # Skip if employee not yet started or already terminated
            start = _to_date(emp["start_date"])
            end   = _to_date(emp["end_date"])
            if start and d < start:
                continue
            if end and d > end:
                continue

            # Base swipe probability
            if _is_weekend(d):
                p_present = 0.35 if is_high_risk else 0.08
            else:
                p_present = 0.92

            if rng.random() > p_present:
                continue  # missed swipe / WFH / travel day

            building = buildings[rng.integers(0, len(buildings))]
            n_swipes = int(rng.integers(2, 8))
            if is_high_risk:
                n_swipes = int(rng.integers(4, 14))  # more after-hours presence

            for _ in range(n_swipes):
                # High-risk: elevated after-hours probability
                if is_high_risk and rng.random() < 0.40:
                    hour = int(rng.choice([0, 1, 2, 3, 4, 5, 20, 21, 22, 23]))
                else:
                    hour = int(rng.integers(7, 20))

                dt = _ts(d, hour=hour)
                door = doors[building][rng.integers(0, len(doors[building]))]
                rec = {
                    "badge_id":       emp["badge_id"],
                    "event_timestamp": _iso(dt),
                    "building_code":  building,
                    "door_id":        door,
                    "location_name":  f"{building} Floor {rng.integers(1,5)}",
                    "direction":      "IN" if rng.random() < 0.5 else "OUT",
                    "after_hours":    _is_after_hours(dt),
                    "weekend":        _is_weekend(d),
                }
                records.append(rec)
    return records


def _gen_network(employees: pd.DataFrame, timeline: list[date]) -> list[dict]:
    """Network events — VPN, DNS, proxy logs."""
    rng = np.random.default_rng(RANDOM_SEED + 20)
    records = []
    event_types = ["vpn_login", "dns_query", "proxy_request", "file_transfer"]

    for _, emp in employees.iterrows():
        emp_id = emp["employee_id"]
        is_high_risk = emp["is_high_risk"]

        for d in timeline:
            if _to_date(emp["end_date"]) and d > _to_date(emp["end_date"]):
                continue

            n_events = int(rng.integers(1, 6))
            if is_high_risk:
                # High risk: more VPN activity at odd hours, burst patterns
                n_events = int(rng.integers(5, 20))

            for _ in range(n_events):
                etype = event_types[rng.integers(0, len(event_types))]
                if is_high_risk and rng.random() < 0.35:
                    hour = int(rng.choice([0, 1, 2, 3, 22, 23]))
                else:
                    hour = int(rng.integers(7, 22))
                dt = _ts(d, hour=hour)
                vpn = (etype == "vpn_login") or (rng.random() < 0.15)
                bytes_xfr = int(rng.integers(1024, 500_000_000)) if is_high_risk else int(rng.integers(512, 5_000_000))

                records.append({
                    "machine_id":          emp["machine_id"],
                    "ip_address":          f"10.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}",
                    "event_timestamp":     _iso(dt),
                    "event_type":          etype,
                    "vpn_flag":            vpn,
                    "dns_query_domain":    f"{rng.choice(['docs','mail','drive','meet','vpn'])}.corp.internal" if not is_high_risk else f"ext-{rng.integers(1,999)}.{rng.choice(['com','io','net'])}",
                    "bytes_transferred":   bytes_xfr,
                    "session_duration_min": round(float(rng.uniform(0.5, 240)), 2),
                    "after_hours":         _is_after_hours(dt),
                })
    return records


def _gen_dlp(employees: pd.DataFrame, timeline: list[date]) -> list[dict]:
    """DLP — file movement, USB writes, print events."""
    rng = np.random.default_rng(RANDOM_SEED + 30)
    records = []
    extensions = [".pdf", ".docx", ".xlsx", ".zip", ".pptx", ".csv", ".sql", ".py"]
    dest_types = ["local", "usb", "cloud", "print", "email_attachment"]

    for _, emp in employees.iterrows():
        is_high_risk = emp["is_high_risk"]

        for d in timeline:
            if _to_date(emp["end_date"]) and d > _to_date(emp["end_date"]):
                continue

            n_events = int(rng.integers(0, 4))
            if is_high_risk:
                # Spike in file movement — especially USB and cloud near window end
                days_elapsed = (d - TIMELINE_START).days
                spike = 1 + (days_elapsed / TIMELINE_DAYS) * 2  # ramp up over time
                n_events = int(rng.integers(3, int(10 * spike) + 4))

            for _ in range(n_events):
                ext = extensions[rng.integers(0, len(extensions))]
                dest = dest_types[rng.integers(0, len(dest_types))]
                if is_high_risk:
                    # Bias toward exfiltration-type destinations
                    dest = rng.choice(["usb", "cloud", "usb", "cloud", "email_attachment", "local"],
                                      p=[0.30, 0.30, 0.15, 0.15, 0.07, 0.03])
                usb = dest == "usb"
                cloud = dest == "cloud"
                print_ = dest == "print"
                file_size = round(float(rng.uniform(0.01, 2048 if is_high_risk else 50)), 2)
                dt = _ts(d)
                records.append({
                    "machine_id":       emp["machine_id"],
                    "user_account":     emp["employee_id"].lower(),
                    "event_timestamp":  _iso(dt),
                    "event_type":       "file_copy" if dest == "local" else f"file_{dest}",
                    "file_name":        f"{rng.integers(1000,9999)}{ext}",
                    "file_extension":   ext,
                    "file_size_mb":     file_size,
                    "destination_type": dest,
                    "usb_flag":         usb,
                    "print_flag":       print_,
                    "cloud_upload_flag": cloud,
                })
    return records


def _gen_comms(employees: pd.DataFrame, timeline: list[date]) -> list[dict]:
    """Communications metadata — email and Slack."""
    rng = np.random.default_rng(RANDOM_SEED + 40)
    records = []

    for _, emp in employees.iterrows():
        is_high_risk = emp["is_high_risk"]

        for d in timeline:
            if _to_date(emp["end_date"]) and d > _to_date(emp["end_date"]):
                continue

            # Comms volume drops sharply in early days then spikes for high-risk
            days_elapsed = (d - TIMELINE_START).days
            n_email = int(rng.integers(2, 15))
            n_slack = int(rng.integers(3, 30))

            if is_high_risk:
                # Volume decline then spike — behavioural shift pattern
                if days_elapsed < 30:
                    n_email = int(rng.integers(8, 20))
                    n_slack = int(rng.integers(15, 50))
                elif days_elapsed < 60:
                    n_email = int(rng.integers(2, 6))   # sudden drop
                    n_slack = int(rng.integers(3, 10))
                else:
                    n_email = int(rng.integers(15, 40))  # spike — unusual burst
                    n_slack = int(rng.integers(5, 15))

            for channel, n in [("email", n_email), ("slack", n_slack)]:
                for _ in range(n):
                    external = rng.random() < (0.25 if is_high_risk else 0.05)
                    attach = rng.random() < (0.30 if is_high_risk else 0.10)
                    hour = int(rng.integers(7, 20))
                    if is_high_risk and rng.random() < 0.20:
                        hour = int(rng.choice([5, 6, 20, 21, 22]))
                    dt = _ts(d, hour=hour)
                    records.append({
                        "email_address":          emp["email_address"],
                        "slack_handle":           emp["slack_handle"],
                        "event_timestamp":        _iso(dt),
                        "channel_type":           channel,
                        "recipient_count":        int(rng.integers(1, 20 if external else 8)),
                        "external_recipient_flag": external,
                        "attachment_flag":        attach,
                        "attachment_size_mb":     round(float(rng.uniform(0.1, 50)), 2) if attach else 0.0,
                        "after_hours":            _is_after_hours(dt),
                    })
    return records


def _gen_pai(employees: pd.DataFrame, timeline: list[date], fake: Faker,
             social_map: pd.DataFrame) -> list[dict]:
    """Public/social media — sentiment scores and post frequency."""
    rng = np.random.default_rng(RANDOM_SEED + 50)
    records = []
    # Build emp_id → (social_handle, platform) lookup — prefer twitter handle for PAI
    twitter_map = social_map[social_map["platform"] == "twitter"]
    handle_lookup = dict(zip(twitter_map["employee_id"], twitter_map["social_handle"]))
    platform_lookup = {eid: "twitter" for eid in handle_lookup}

    for _, emp in employees.iterrows():
        is_high_risk = emp["is_high_risk"]
        social_handle = handle_lookup.get(emp["employee_id"])
        if social_handle is None:
            continue  # unmapped — no PAI data for this employee

        # Personal baseline sentiment (stable for normal employees)
        baseline_sentiment = float(rng.uniform(0.1, 0.8))

        for d in timeline:
            if _to_date(emp["end_date"]) and d > _to_date(emp["end_date"]):
                continue
            # Post only a few times a week
            if rng.random() > 0.35:
                continue

            days_elapsed = (d - TIMELINE_START).days
            if is_high_risk:
                # Sentiment decline over time — key signal
                decline = (days_elapsed / TIMELINE_DAYS) * 1.2
                sentiment = float(np.clip(baseline_sentiment - decline + rng.uniform(-0.1, 0.1), -1.0, 1.0))
            else:
                sentiment = float(np.clip(baseline_sentiment + rng.uniform(-0.15, 0.15), -1.0, 1.0))

            dt = _ts(d)
            records.append({
                "social_handle":    social_handle,
                "event_timestamp":  _iso(dt),
                "platform":         platform_lookup.get(emp["employee_id"], "twitter"),
                "sentiment_score":  round(sentiment, 4),
                "post_count":       int(rng.integers(1, 5)),
                "engagement_count": int(rng.integers(0, 200)),
            })
    return records


def _gen_geo(employees: pd.DataFrame, timeline: list[date]) -> list[dict]:
    """Geospatial building location events."""
    rng = np.random.default_rng(RANDOM_SEED + 60)
    records = []
    # Building centroids (fictional)
    buildings = {
        "HQ-A":        (38.8951, -77.0364),
        "HQ-B":        (38.8953, -77.0370),
        "DATA-CENTER": (38.9010, -77.0400),
        "ANNEX-1":     (38.8900, -77.0310),
    }
    device_types = ["laptop", "mobile", "badge_reader", "desktop"]

    for _, emp in employees.iterrows():
        is_high_risk = emp["is_high_risk"]

        for d in timeline:
            if _to_date(emp["end_date"]) and d > _to_date(emp["end_date"]):
                continue
            if rng.random() > 0.7:
                continue  # not every employee has geo data every day

            building = rng.choice(list(buildings.keys()))
            lat_base, lon_base = buildings[building]
            dt = _ts(d)

            rec = {
                "badge_id":        emp["badge_id"],
                "device_id":       f"DEV_{emp['employee_id']}_{rng.integers(1,4)}",
                "event_timestamp": _iso(dt),
                "building_code":   building,
                "latitude":        round(lat_base + float(rng.uniform(-0.001, 0.001)), 6),
                "longitude":       round(lon_base + float(rng.uniform(-0.001, 0.001)), 6),
                "device_type":     device_types[rng.integers(0, len(device_types))],
            }

            # Impossible travel: inject for ~5 high-risk employees on random days
            if is_high_risk and rng.random() < 0.08:
                # Second record same day, distant location
                dt2 = _ts(d, hour=dt.hour + 1 if dt.hour < 23 else 0)
                records.append(rec)
                records.append({
                    "badge_id":        emp["badge_id"],
                    "device_id":       f"DEV_{emp['employee_id']}_remote",
                    "event_timestamp": _iso(dt2),
                    "building_code":   "OFFSITE",
                    "latitude":        round(float(rng.uniform(25.0, 48.0)), 6),
                    "longitude":       round(float(rng.uniform(-120.0, -70.0)), 6),
                    "device_type":     "mobile",
                })
                continue
            records.append(rec)
    return records


def _gen_adjudication(employees: pd.DataFrame, timeline: list[date]) -> list[dict]:
    """Security clearance adjudication events."""
    rng = np.random.default_rng(RANDOM_SEED + 70)
    records = []

    for _, emp in employees.iterrows():
        is_high_risk = emp["is_high_risk"]
        # Each employee gets a baseline clearance record at timeline start
        reinvest_due = TIMELINE_START + timedelta(days=int(rng.integers(180, 1095)))
        status_change = False

        # High-risk: ~40% have a status change or reinvestigation flag mid-window
        if is_high_risk and rng.random() < 0.40:
            change_day = TIMELINE_START + timedelta(days=int(rng.integers(20, 70)))
            records.append({
                "employee_id":            emp["employee_id"],
                "event_timestamp":        _iso(_ts(change_day)),
                "clearance_level":        emp["clearance_level"],
                "clearance_status":       rng.choice(["UNDER_REVIEW", "SUSPENDED"]),
                "investigation_flag":     True,
                "reinvestigation_due_date": reinvest_due.isoformat(),
                "status_change_flag":     True,
            })

        # Baseline record
        records.append({
            "employee_id":            emp["employee_id"],
            "event_timestamp":        _iso(_ts(TIMELINE_START)),
            "clearance_level":        emp["clearance_level"],
            "clearance_status":       "ACTIVE",
            "investigation_flag":     False,
            "reinvestigation_due_date": reinvest_due.isoformat(),
            "status_change_flag":     False,
        })
    return records


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def _write_csv(df: pd.DataFrame, path: Path, dry_run: bool) -> str:
    if dry_run:
        logger.info("[DRY-RUN] Would write %d rows to %s", len(df), path)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(path, index=False)
        logger.info("Wrote %d rows to %s", len(df), path)
    return str(path)


def _records_to_csv(records: list[dict], path: Path, dry_run: bool) -> str:
    """Write a list of dicts to CSV (replaces _write_json — all Bronze files are CSV now)."""
    return _write_csv(pd.DataFrame(records), path, dry_run)


def _s3_client():
    """Return a boto3 S3 client pointed at MinIO."""
    return boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        region_name=MINIO_REGION,
        config=Config(signature_version="s3v4"),
    )


def _upload_to_minio(paths: list[str], dry_run: bool) -> list[str]:
    """Upload all Bronze CSV files to MinIO. Returns list of s3:// URIs."""
    if dry_run:
        uris = [f"s3://{MINIO_BUCKET}/{MINIO_PREFIX}/{Path(p).name}" for p in paths]
        logger.info("[DRY-RUN] Would upload %d files to MinIO", len(paths))
        return uris

    s3 = _s3_client()
    uris = []
    for local_path in paths:
        key = f"{MINIO_PREFIX}/{Path(local_path).name}"
        s3.upload_file(local_path, MINIO_BUCKET, key)
        uri = f"s3://{MINIO_BUCKET}/{key}"
        logger.info("Uploaded %s -> %s", Path(local_path).name, uri)
        uris.append(uri)
    return uris


# ---------------------------------------------------------------------------
# Schema documentation
# ---------------------------------------------------------------------------

def _write_schema_map(dry_run: bool) -> None:
    schema = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domains": {
            "hris_events.csv":         {"native_id": "employee_id",                  "format": "csv"},
            "pacs_events.csv":         {"native_id": "badge_id",                     "format": "csv"},
            "dlp_events.csv":          {"native_id": ["machine_id","user_account"],  "format": "csv"},
            "network_events.csv":      {"native_id": ["machine_id","ip_address"],    "format": "csv"},
            "adjudication_events.csv": {"native_id": "employee_id",                  "format": "csv"},
            "comms_events.csv":        {"native_id": ["email_address","slack_handle"],"format": "csv"},
            "pai_events.csv":          {"native_id": "social_handle",                "format": "csv"},
            "geo_events.csv":          {"native_id": ["badge_id","device_id"],       "format": "csv"},
        },
        "mapping_tables": {
            "badge_registry.csv":     "badge_id → employee_id",
            "asset_assignment.csv":   "machine_id → employee_id (effective dates)",
            "directory.csv":          "email_address, slack_handle → employee_id",
            "social_handle_map.csv":  "social_handle → employee_id (~5% unmapped)",
        },
    }
    path = _PROJECT_ROOT / "schema" / "bronze_schema_map.json"
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(schema, indent=2))
    logger.info("Schema map: %s", path)


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(dry_run: bool = False, env: str = "local", log_level: str = "INFO") -> dict:
    """
    Generate all Bronze synthetic data files.

    Returns standard stage result dict.
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    t0 = time.perf_counter()
    logger.info("s1_generate_raw START | dry_run=%s env=%s seed=%d employees=%d days=%d",
                dry_run, env, RANDOM_SEED, EMPLOYEE_COUNT, TIMELINE_DAYS)

    _seed_all(RANDOM_SEED)
    fake = Faker()
    timeline = _timeline()
    artifacts: list[str] = []

    try:
        # ---- Employee master (internal only — not written as a domain file) ----
        logger.info("Building employee master...")
        employees = _build_employee_master(fake)
        rows_in = 0  # Bronze has no upstream input

        # ---- Mapping tables ----
        logger.info("Generating mapping tables...")
        badge_reg  = _gen_badge_registry(employees)
        asset_asgn = _gen_asset_assignment(employees)
        directory  = _gen_directory(employees)
        social_map = _gen_social_handle_map(employees, fake)

        artifacts.append(_write_csv(badge_reg,  BRONZE_DIR / "badge_registry.csv",  dry_run))
        artifacts.append(_write_csv(asset_asgn, BRONZE_DIR / "asset_assignment.csv", dry_run))
        artifacts.append(_write_csv(directory,  BRONZE_DIR / "directory.csv",        dry_run))
        artifacts.append(_write_csv(social_map, BRONZE_DIR / "social_handle_map.csv", dry_run))

        # ---- Domain files ----
        logger.info("Generating HRIS events...")
        hris = _gen_hris(employees)
        artifacts.append(_write_csv(hris, BRONZE_DIR / "hris_events.csv", dry_run))

        logger.info("Generating PACS events...")
        pacs = _gen_pacs(employees, timeline)
        artifacts.append(_records_to_csv(pacs, BRONZE_DIR / "pacs_events.csv", dry_run))

        logger.info("Generating network events...")
        network = _gen_network(employees, timeline)
        artifacts.append(_records_to_csv(network, BRONZE_DIR / "network_events.csv", dry_run))

        logger.info("Generating DLP events...")
        dlp = _gen_dlp(employees, timeline)
        artifacts.append(_records_to_csv(dlp, BRONZE_DIR / "dlp_events.csv", dry_run))

        logger.info("Generating comms events...")
        comms = _gen_comms(employees, timeline)
        artifacts.append(_write_csv(pd.DataFrame(comms), BRONZE_DIR / "comms_events.csv", dry_run))

        logger.info("Generating PAI events...")
        pai = _gen_pai(employees, timeline, fake, social_map)
        artifacts.append(_write_csv(pd.DataFrame(pai), BRONZE_DIR / "pai_events.csv", dry_run))

        logger.info("Generating geo events...")
        geo = _gen_geo(employees, timeline)
        artifacts.append(_records_to_csv(geo, BRONZE_DIR / "geo_events.csv", dry_run))

        logger.info("Generating adjudication events...")
        adj = _gen_adjudication(employees, timeline)
        artifacts.append(_write_csv(pd.DataFrame(adj), BRONZE_DIR / "adjudication_events.csv", dry_run))

        # ---- Upload all CSV files to MinIO ----
        local_files = [a for a in artifacts if a.endswith(".csv")]
        logger.info("Uploading %d files to MinIO bucket %s...", len(local_files), MINIO_BUCKET)
        s3_uris = _upload_to_minio(local_files, dry_run)
        artifacts.extend(s3_uris)

        _write_schema_map(dry_run)

        # Row counts (internal streams)
        internal_rows = (
            len(badge_reg) + len(asset_asgn) + len(directory) + len(social_map)
            + len(hris) + len(pacs) + len(network) + len(dlp)
            + len(comms) + len(pai) + len(geo) + len(adj)
        )

        # ---- OSINT Bronze streams ----
        logger.info("Generating OSINT Bronze streams...")
        osint_result = generate_osint_streams.run(
            dry_run=dry_run, env=env, log_level=log_level
        )
        if osint_result["status"] != "success":
            raise RuntimeError(f"OSINT generation failed: {osint_result}")
        artifacts.extend(osint_result["artifacts"])
        osint_rows = osint_result["rows_out"]

        rows_out = internal_rows + osint_rows

        duration = time.perf_counter() - t0
        logger.info("s1_generate_raw DONE | rows_out=%d (internal=%d osint=%d) duration=%.2fs",
                    rows_out, internal_rows, osint_rows, duration)

        # Summary log
        logger.info("Row counts — badge_registry:%d asset_assignment:%d directory:%d "
                    "social_handle_map:%d hris:%d pacs:%d network:%d dlp:%d "
                    "comms:%d pai:%d geo:%d adjudication:%d osint:%d",
                    len(badge_reg), len(asset_asgn), len(directory), len(social_map),
                    len(hris), len(pacs), len(network), len(dlp),
                    len(comms), len(pai), len(geo), len(adj), osint_rows)

        return {
            "status": "success",
            "rows_in": rows_in,
            "rows_out": rows_out,
            "duration_seconds": round(duration, 3),
            "artifacts": artifacts,
        }

    except Exception as exc:
        duration = time.perf_counter() - t0
        logger.exception("s1_generate_raw FAILED: %s", exc)
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
    p = argparse.ArgumentParser(description="s1_generate_raw — synthetic data generation")
    p.add_argument("--dry-run",  action="store_true", help="Validate but do not write files")
    p.add_argument("--env",      default="local", choices=["local", "dev", "prod"])
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING"])
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    result = run(dry_run=args.dry_run, env=args.env, log_level=args.log_level)
    print(json.dumps(result, indent=2))
