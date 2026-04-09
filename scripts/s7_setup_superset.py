"""
s7_setup_superset.py — Automated Superset dashboard setup for Sentinel-TDI.

Dashboard layout — three catalog tables showing the full data lineage:

  Source (Bronze Layer)
    List of source files and external tables — description + record count

  EDW (Silver Layer)
    List of conformed domain tables — description + record count

  Analytics (Gold Layer)
    List of Gold tables — description + record count

Usage:
    cd scripts
    python s7_setup_superset.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ---------------------------------------------------------------------------
# Config — all from environment variables
# ---------------------------------------------------------------------------

SUPERSET_URL      = os.getenv("SUPERSET_URL",      "")
SUPERSET_USER     = os.getenv("SUPERSET_USER",     "")
SUPERSET_PASSWORD = os.getenv("SUPERSET_PASSWORD", "")

GP_HOST     = os.getenv("GP_HOST",     "localhost")
GP_PORT     = os.getenv("GP_PORT",     "5432")
GP_DB       = os.getenv("GP_DB",       "gpadmin")
GP_USER     = os.getenv("GP_USER",     "gpadmin")
GP_PASSWORD = os.getenv("GP_PASSWORD", "")

BRONZE_SCHEMA = "insider_threat_bronze"
SILVER_SCHEMA = "insider_threat_silver"
GOLD_SCHEMA   = "insider_threat_gold"

DB_DISPLAY_NAME = "Sentinel-TDI Greenplum"
DASHBOARD_TITLE = "Sentinel TDI — Insider Threat Detection"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("s7_setup_superset")


# ---------------------------------------------------------------------------
# Superset API client
# ---------------------------------------------------------------------------

class SupersetClient:
    """Thin wrapper around the Superset REST API v1."""

    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._login(username, password)

    def _login(self, username: str, password: str) -> None:
        resp = self.session.post(
            f"{self.base_url}/api/v1/security/login",
            json={"username": username, "password": password,
                  "provider": "db", "refresh": True},
        )
        resp.raise_for_status()
        token = resp.json()["access_token"]
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Referer": self.base_url,
        })
        csrf_resp = self.session.get(f"{self.base_url}/api/v1/security/csrf_token/")
        csrf_resp.raise_for_status()
        self.session.headers.update({"X-CSRFToken": csrf_resp.json()["result"]})
        logger.info("Authenticated to Superset at %s", self.base_url)

    def get(self, path: str, **kwargs: Any) -> Any:
        resp = self.session.get(f"{self.base_url}{path}", **kwargs)
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, payload: dict) -> Any:
        resp = self.session.post(f"{self.base_url}{path}", json=payload)
        if not resp.ok:
            logger.error("POST %s failed %d: %s", path, resp.status_code, resp.text[:1500])
            logger.error("POST payload keys: %s", list(payload.keys()))
        resp.raise_for_status()
        return resp.json()

    def put(self, path: str, payload: dict) -> Any:
        resp = self.session.put(f"{self.base_url}{path}", json=payload)
        if not resp.ok:
            logger.error("PUT %s failed %d: %s", path, resp.status_code, resp.text[:400])
        resp.raise_for_status()
        return resp.json()

    def delete(self, path: str) -> None:
        resp = self.session.delete(f"{self.base_url}{path}")
        if not resp.ok and resp.status_code != 404:
            logger.warning("DELETE %s returned %d", path, resp.status_code)

    def find_by_name(self, path: str, col: str, value: str) -> dict | None:
        q = json.dumps({"filters": [{"col": col, "opr": "eq", "value": value}]})
        try:
            data = self.get(path, params={"q": q})
            results = data.get("result", [])
            return results[0] if results else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Teardown — remove previous version of this dashboard cleanly
# ---------------------------------------------------------------------------

_OLD_CHART_NAMES = [
    "Employees Scored", "HIGH Risk Employees", "Silver Domains Loaded",
    "Pipeline Stages Run", "Anomaly Tier Distribution",
    "Top 25 Highest Risk Employees", "Silver Identity Resolution by Domain",
    "Pipeline Run Audit",
    # new names
    "Source — Bronze Layer", "EDW — Silver Layer", "Analytics — Gold Layer",
]

_OLD_DATASET_NAMES = [
    "employee_risk_features", "pipeline_runs",
    "silver_resolution_summary", "gold_latest_window",
    "bronze_catalog", "silver_catalog", "gold_catalog",
    # OSINT datasets (if ever created as separate datasets)
    "osint_bronze_catalog", "osint_silver_catalog", "osint_gold_catalog",
]


def teardown(client: SupersetClient) -> None:
    """Remove any prior version of this dashboard, its charts, and datasets."""
    # Dashboard
    existing = client.find_by_name("/api/v1/dashboard/", "dashboard_title", DASHBOARD_TITLE)
    if existing:
        client.delete(f"/api/v1/dashboard/{existing['id']}")
        logger.info("Deleted dashboard: %s", DASHBOARD_TITLE)

    # Charts
    for name in _OLD_CHART_NAMES:
        existing = client.find_by_name("/api/v1/chart/", "slice_name", name)
        if existing:
            client.delete(f"/api/v1/chart/{existing['id']}")
            logger.info("Deleted chart: %s", name)

    # Datasets
    for name in _OLD_DATASET_NAMES:
        existing = client.find_by_name("/api/v1/dataset/", "table_name", name)
        if existing:
            client.delete(f"/api/v1/dataset/{existing['id']}")
            logger.info("Deleted dataset: %s", name)


# ---------------------------------------------------------------------------
# 1. Database
# ---------------------------------------------------------------------------

def setup_database(client: SupersetClient) -> int:
    existing = client.find_by_name("/api/v1/database/", "database_name", DB_DISPLAY_NAME)
    if existing:
        logger.info("Database already registered: %s (id=%d)", DB_DISPLAY_NAME, existing["id"])
        return existing["id"]

    uri = f"postgresql+psycopg2://{GP_USER}:{GP_PASSWORD}@{GP_HOST}:{GP_PORT}/{GP_DB}"
    result = client.post("/api/v1/database/", {
        "database_name": DB_DISPLAY_NAME,
        "sqlalchemy_uri": uri,
        "expose_in_sqllab": True,
        "allow_run_async": True,
        "allow_ctas": False,
        "allow_cvas": False,
        "allow_dml": False,
    })
    logger.info("Created database: %s (id=%d)", DB_DISPLAY_NAME, result["id"])
    return result["id"]


# ---------------------------------------------------------------------------
# 2. Datasets — one virtual SQL dataset per layer
# ---------------------------------------------------------------------------

def _bronze_sql() -> str:
    # (priority, display_name, gp_table, description)
    rows = [
        # ── Enterprise behavioral signals ────────────────────────────────────────
        ( 1, "HR Master",
          f"{BRONZE_SCHEMA}.ext_hris_events",
          "Identity anchor — who the person is, their role, clearance level, and current employment status. Every other signal is interpreted against this record."),
        ( 2, "Data Activity",
          f"{BRONZE_SCHEMA}.ext_dlp_events",
          "Closest signal to actual harm — file exfiltration, USB writes, and cloud uploads of sensitive documents. This is where the damage happens."),
        ( 3, "System Activity",
          f"{BRONZE_SCHEMA}.ext_network_events",
          "Precursor to data activity — VPN anomalies, suspicious external domains, and after-hours sessions. The digital setup that typically precedes an exfiltration event."),
        ( 4, "Communications",
          f"{BRONZE_SCHEMA}.ext_comms_events",
          "Intent signal — external recipient spikes, large attachments to personal email, and messaging volume shifts. Often correlated same-day with data activity."),
        ( 5, "Building Access",
          f"{BRONZE_SCHEMA}.ext_pacs_events",
          "Physical behavioral pattern — after-hours server room access and sensitive area visits. Strong corroborating signal that rarely stands alone."),
        ( 6, "Security Clearance",
          f"{BRONZE_SCHEMA}.ext_adjudication_events",
          "Formal risk indicator — active reinvestigations, status suspensions, and clearance changes. The organization's own adjudication process flagging elevated concern."),
        # ── External intelligence signals ────────────────────────────────────────
        ( 7, "Dark Web Alerts",
          f"{BRONZE_SCHEMA}.ext_raw_darkweb_signals",
          "Risk amplifier and confirmation signal — employee credentials found in breach databases. Raises the severity of any correlated internal behavior and may indicate unauthorized access using stolen credentials."),
        ( 8, "Financial Stress",
          f"{BRONZE_SCHEMA}.ext_raw_financial_stress",
          "Motive signal — court filings, liens, and judgments from public records. The why behind the behavior. Typically surfaces 2 to 4 weeks ahead of internal behavioral changes."),
        ( 9, "Lifestyle Incongruity",
          f"{BRONZE_SCHEMA}.ext_raw_lifestyle_signals",
          "Motive signal — spending patterns and lifestyle indicators inconsistent with known salary level. Often surfaces earlier than financial stress records in the public domain."),
        (10, "Social Sentiment",
          f"{BRONZE_SCHEMA}.ext_pai_events",
          "Behavioral drift — declining mood scores and emotional keyword flags from public social activity. Confirms stress is building but rarely actionable without corroborating signals."),
        (11, "Twitter / X Activity",
          f"{BRONZE_SCHEMA}.ext_raw_tweets",
          "Raw social feed powering the sentiment analysis — individual posts, retweet patterns, and engagement signals from monitored accounts."),
        (12, "Campus Location Data",
          f"{BRONZE_SCHEMA}.ext_geo_events",
          "Corroborating physical signal — device detection in restricted zones and campus areas. Most valuable for timeline reconstruction after an event rather than early detection."),
        (13, "Public Location Activity",
          f"{BRONZE_SCHEMA}.ext_raw_instagram_posts",
          "External location signal — public check-ins and location posts from monitored social accounts. Useful for corroboration but requires supporting evidence from other streams."),
        # ── Identity registers ────────────────────────────────────────────────────
        (14, "Door & Badge Register",
          f"{BRONZE_SCHEMA}.ext_badge_registry",
          "Links every physical access badge to the employee it belongs to. Connects building entry events to an individual's HR record."),
        (15, "Workstation Register",
          f"{BRONZE_SCHEMA}.ext_asset_assignment",
          "Tracks which employee uses which computer and when assignments changed. Attributes file and network activity to the responsible individual."),
        (16, "Corporate Directory",
          f"{BRONZE_SCHEMA}.ext_directory",
          "Maps employee email addresses and messaging handles to their HR profile. Connects email and Slack activity to a known employee."),
        (17, "Social Media Identity Register",
          f"{BRONZE_SCHEMA}.ext_social_handle_map",
          "Links public social media accounts to employee HR records. Connects external social and OSINT signals to a known person in the organization."),
    ]
    unions = "\n    UNION ALL\n    ".join(
        f"SELECT {priority} AS priority, '{name}' AS source_name, '{desc.replace(chr(39), chr(39)+chr(39))}' AS description, COUNT(*)::INT AS record_count FROM {table}"
        for priority, name, table, desc in rows
    )
    return f"SELECT source_name, description, record_count FROM (\n    {unions}\n) t ORDER BY priority"


def _silver_sql() -> str:
    # (priority, display_name, gp_table, description)
    rows = [
        # ── Enterprise behavioral records ─────────────────────────────────────────
        ( 1, "Employee Records",
          f"{SILVER_SCHEMA}.sv_hris",
          "Every employee's full profile — department, job title, clearance level, and employment dates. The authoritative identity record that all other tables link back to."),
        ( 2, "Data Activity Events",
          f"{SILVER_SCHEMA}.sv_dlp",
          "File movement events resolved to the responsible employee — USB transfers, cloud uploads, print jobs, and document copies with file size and destination."),
        ( 3, "System Activity Events",
          f"{SILVER_SCHEMA}.sv_network",
          "Network and computer sessions resolved to the employee — VPN logins, external site visits, data volumes transferred, and after-hours session flags."),
        ( 4, "Communications Events",
          f"{SILVER_SCHEMA}.sv_comms",
          "Email and messaging records resolved to the employee — external contact flags, attachment sizes, and volume changes over time."),
        ( 5, "Building Access Events",
          f"{SILVER_SCHEMA}.sv_pacs",
          "Badge entry and exit events resolved to the employee — door location, time of day, and after-hours and weekend flags."),
        ( 6, "Security Clearance Events",
          f"{SILVER_SCHEMA}.sv_adjudication",
          "Clearance status history resolved to the employee — active investigations, reinvestigation deadlines, and status change events."),
        ( 7, "Dark Web Detections",
          f"{SILVER_SCHEMA}.silver_darkweb_signals",
          "Breach database matches resolved to the employee — credential type, source, severity level, and confidence score for each detection."),
        ( 8, "Financial Stress Records",
          f"{SILVER_SCHEMA}.silver_financial_stress",
          "Public financial distress records linked to the employee by name — court filings, liens, and judgments with stress severity scores."),
        ( 9, "Lifestyle Risk Signals",
          f"{SILVER_SCHEMA}.silver_lifestyle_incongruity",
          "Public spending and lifestyle events linked to the employee — estimated value, salary band comparison, and an incongruity score relative to compensation."),
        (10, "Social Sentiment",
          f"{SILVER_SCHEMA}.sv_pai",
          "Daily mood and engagement signals from public social accounts linked to the employee — sentiment score, post frequency, and emotional keyword tags."),
        (11, "Campus Location Events",
          f"{SILVER_SCHEMA}.sv_geo",
          "Device position records on campus resolved to the employee — building zone, coordinates, and device type."),
        (12, "Location Anomalies",
          f"{SILVER_SCHEMA}.silver_geo_anomalies",
          "Public location check-ins linked to the employee — classified by location sensitivity with anomaly and incongruity flags."),
        (13, "Unlinked Event Log",
          f"{SILVER_SCHEMA}.sv_unresolved_events",
          "Events from all sources that could not be linked to a known employee — retained for audit and coverage reporting."),
    ]
    unions = "\n    UNION ALL\n    ".join(
        f"SELECT {priority} AS priority, '{name}' AS table_name, '{desc.replace(chr(39), chr(39)+chr(39))}' AS description, COUNT(*)::INT AS record_count FROM {table}"
        for priority, name, table, desc in rows
    )
    return f"SELECT table_name, description, record_count FROM (\n    {unions}\n) t ORDER BY priority"


def _gold_sql() -> str:
    # (priority, display_name, gp_table, description)
    rows = [
        # ── Composite output — the primary analyst view ───────────────────────────
        ( 1, "Composite Risk Score",
          f"{GOLD_SCHEMA}.gold_composite_risk",
          "Weekly fused risk score per employee combining all six behavioral streams. Includes risk tier (Low / Medium / High / Critical), primary signal driver, and recommended action."),
        # ── Individual stream scores ──────────────────────────────────────────────
        ( 2, "Behavioral Risk Profile",
          f"{GOLD_SCHEMA}.employee_risk_features",
          "Weekly internal behavioral risk score per employee — derived from 13 signals across building access, system activity, data movement, communications, location, sentiment, and clearance status."),
        ( 3, "Financial Stress Risk",
          f"{GOLD_SCHEMA}.gold_financial_stress_risk",
          "Weekly financial risk score per employee — based on active public records count and cumulative stress score from court filings, liens, and judgments."),
        ( 4, "Dark Web Risk",
          f"{GOLD_SCHEMA}.gold_darkweb_risk",
          "Weekly dark web risk score per employee — based on breach detection count and maximum severity across detections in the period."),
        ( 5, "Lifestyle Risk",
          f"{GOLD_SCHEMA}.gold_lifestyle_risk",
          "Weekly lifestyle incongruity risk score per employee — based on unexplained spending event count, maximum incongruity score, and cumulative 30-day spend."),
        ( 6, "Social Sentiment Risk",
          f"{GOLD_SCHEMA}.gold_twitter_risk",
          "Weekly sentiment risk score per employee — based on the gap between current mood and the employee's personal 30-day baseline, with primary emotional signal flagged."),
        ( 7, "Location Risk",
          f"{GOLD_SCHEMA}.gold_location_risk",
          "Weekly location risk score per employee — based on sensitive location visit count and work-hours absence patterns from public check-in data."),
        # ── Scoring model internals ───────────────────────────────────────────────
        ( 8, "Peer Group Model",
          f"{GOLD_SCHEMA}.gd_kmeans_output",
          "The behavioral peer group model — five clusters representing distinct behavioral profiles learned from the full employee population. Each employee is assigned to the closest matching group."),
        ( 9, "Individual Score Results",
          f"{GOLD_SCHEMA}.gd_scored",
          "Per-employee, per-week distance from assigned peer group — the raw anomaly signal before normalization and tier assignment."),
        (10, "Scoring Input Vectors",
          f"{GOLD_SCHEMA}.employee_features",
          "Normalized behavioral feature vectors used as input to the peer group scoring model — one row per employee per week."),
    ]
    unions = "\n    UNION ALL\n    ".join(
        f"SELECT {priority} AS priority, '{name}' AS table_name, '{desc.replace(chr(39), chr(39)+chr(39))}' AS description, COUNT(*)::INT AS record_count FROM {table}"
        for priority, name, table, desc in rows
    )
    return f"SELECT table_name, description, record_count FROM (\n    {unions}\n) t ORDER BY priority"


def setup_datasets(client: SupersetClient, db_id: int) -> dict[str, int]:
    datasets = {}
    for name, sql in [
        ("bronze_catalog", _bronze_sql()),
        ("silver_catalog", _silver_sql()),
        ("gold_catalog",   _gold_sql()),
    ]:
        existing = client.find_by_name("/api/v1/dataset/", "table_name", name)
        if existing:
            ds_id = existing["id"]
            client.put(f"/api/v1/dataset/{ds_id}", {"sql": sql})
            datasets[name] = ds_id
            logger.info("Updated existing dataset: %s (id=%d)", name, ds_id)
        else:
            # Superset 3.x rejects complex SQL in POST — create with stub, then PUT real SQL
            result = client.post("/api/v1/dataset/", {
                "database": db_id,
                "table_name": name,
                "sql": "SELECT 1 AS placeholder",
            })
            ds_id = result["id"]
            client.put(f"/api/v1/dataset/{ds_id}", {"sql": sql})
            datasets[name] = ds_id
            logger.info("Created dataset: %s (id=%d)", name, ds_id)
        # Register columns explicitly — Superset doesn't auto-discover from virtual SQL
        col_name = "source_name" if name == "bronze_catalog" else "table_name"
        cols = [
            {"column_name": col_name,       "type": "VARCHAR", "is_dttm": False, "filterable": True, "groupby": True},
            {"column_name": "description",  "type": "VARCHAR", "is_dttm": False, "filterable": True, "groupby": True},
            {"column_name": "record_count", "type": "INTEGER", "is_dttm": False, "filterable": True, "groupby": True},
        ]
        client.put(f"/api/v1/dataset/{ds_id}", {"columns": cols})
        logger.info("Registered columns for dataset: %s (id=%d)", name, ds_id)
    return datasets


# ---------------------------------------------------------------------------
# 3. Charts — one table chart per layer
# ---------------------------------------------------------------------------

def _table_params(ds_id: int, name_col: str) -> tuple[str, str]:
    """Return (params_json, query_context_json) for a catalog table chart."""
    params = {
        "viz_type": "table",
        "datasource": f"{ds_id}__table",
        "adhoc_filters": [],
        "time_range": "No filter",
        "query_mode": "raw",
        "columns": [name_col, "description", "record_count"],
        "metrics": [],
        "row_limit": 25,
        "order_desc": False,
        "server_pagination": False,
        "align_pn": False,
        "color_pn": False,
        "page_length": 25,
        "show_totals": False,
        "conditional_formatting": [],
    }
    query_context = {
        "datasource": {"id": ds_id, "type": "table"},
        "force": False,
        "queries": [{
            "metrics": [],
            "filters": [],
            "row_limit": 25,
            "orderby": [],
            "extras": {},
            "time_range": "No filter",
            "columns": [name_col, "description", "record_count"],
            "groupby": [],
        }],
        "result_format": "json",
        "result_type": "full",
    }
    return json.dumps(params), json.dumps(query_context)


def setup_charts(client: SupersetClient, datasets: dict[str, int]) -> list[int]:
    specs = [
        {
            "slice_name": "Source — Bronze Layer",
            "ds_name": "bronze_catalog",
            "name_col": "source_name",
        },
        {
            "slice_name": "EDW — Silver Layer",
            "ds_name": "silver_catalog",
            "name_col": "table_name",
        },
        {
            "slice_name": "Analytics — Gold Layer",
            "ds_name": "gold_catalog",
            "name_col": "table_name",
        },
    ]

    chart_ids: list[int] = []
    for spec in specs:
        ds_id = datasets[spec["ds_name"]]
        params, query_context = _table_params(ds_id, spec["name_col"])
        result = client.post("/api/v1/chart/", {
            "slice_name":      spec["slice_name"],
            "viz_type":        "table",
            "datasource_id":   ds_id,
            "datasource_type": "table",
            "params":          params,
            "query_context":   query_context,
        })
        chart_ids.append(result["id"])
        logger.info("Created chart: %s (id=%d)", spec["slice_name"], result["id"])

    return chart_ids


# ---------------------------------------------------------------------------
# 4. Dashboard
# ---------------------------------------------------------------------------

def _build_position_json(chart_ids: list[int]) -> str:
    """One row, three columns — Bronze | Silver | Gold, each width=8."""
    chart_node_ids = ["CHART-BRONZE", "CHART-SILVER", "CHART-GOLD"]

    layout: dict[str, Any] = {
        "DASHBOARD_VERSION_KEY": "v2",
        "ROOT_ID": {"type": "ROOT", "id": "ROOT_ID", "children": ["GRID_ID"]},
        "GRID_ID": {
            "type": "GRID", "id": "GRID_ID",
            "children": ["ROW-MAIN"],
            "parents": ["ROOT_ID"],
        },
        "ROW-MAIN": {
            "type": "ROW", "id": "ROW-MAIN",
            "children": chart_node_ids, "parents": ["GRID_ID"],
            "meta": {"background": "BACKGROUND_TRANSPARENT"},
        },
    }

    for node_id, chart_id in zip(chart_node_ids, chart_ids):
        layout[node_id] = {
            "type": "CHART", "id": node_id,
            "children": [], "parents": ["ROW-MAIN"],
            "meta": {"chartId": chart_id, "width": 8, "height": 38},
        }

    return json.dumps(layout)


def setup_dashboard(client: SupersetClient, chart_ids: list[int]) -> int:
    result = client.post("/api/v1/dashboard/", {
        "dashboard_title": DASHBOARD_TITLE,
        "published": True,
        "position_json": _build_position_json(chart_ids),
    })
    dash_id = result["id"]

    for cid in chart_ids:
        client.put(f"/api/v1/chart/{cid}", {"dashboards": [dash_id]})

    logger.info("Created dashboard: %s (id=%d)", DASHBOARD_TITLE, dash_id)
    return dash_id


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> dict:
    missing = [v for v in ["SUPERSET_URL", "SUPERSET_USER", "SUPERSET_PASSWORD", "GP_PASSWORD"]
               if not os.getenv(v)]
    if missing:
        logger.error("Missing required env vars: %s", ", ".join(missing))
        sys.exit(1)

    t0 = time.perf_counter()

    client = SupersetClient(SUPERSET_URL, SUPERSET_USER, SUPERSET_PASSWORD)

    logger.info("Step 1/5 — Tear down previous version")
    teardown(client)

    logger.info("Step 2/5 — Register Greenplum database")
    db_id = setup_database(client)

    logger.info("Step 3/5 — Create datasets")
    datasets = setup_datasets(client, db_id)

    logger.info("Step 4/5 — Create charts")
    chart_ids = setup_charts(client, datasets)

    logger.info("Step 5/5 — Create dashboard")
    dash_id = setup_dashboard(client, chart_ids)

    duration = time.perf_counter() - t0
    url = f"{SUPERSET_URL}/superset/dashboard/{dash_id}/"
    logger.info("Done in %.1fs", duration)
    print(f"\nDashboard ready: {url}\n")

    return {"status": "success", "dashboard_id": dash_id, "dashboard_url": url}


if __name__ == "__main__":
    run()
