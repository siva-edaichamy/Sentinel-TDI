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
            logger.error("POST %s failed %d: %s", path, resp.status_code, resp.text[:400])
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
    rows = [
        # Internal enterprise sources
        ("ext_hris_events",         f"{BRONZE_SCHEMA}.ext_hris_events",         "1. HR records — employee names, job titles, departments, hire/termination dates, and security clearance levels"),
        ("ext_pacs_events",         f"{BRONZE_SCHEMA}.ext_pacs_events",         "2. Building access — when each employee entered or exited each door, including early morning and late night visits"),
        ("ext_network_events",      f"{BRONZE_SCHEMA}.ext_network_events",      "3. Computer activity — VPN logins, websites visited, data downloaded, and remote access sessions"),
        ("ext_dlp_events",          f"{BRONZE_SCHEMA}.ext_dlp_events",          "4. File movement — documents copied to USB drives, uploaded to cloud services, or sent to printers"),
        ("ext_comms_events",        f"{BRONZE_SCHEMA}.ext_comms_events",        "5. Messaging activity — email and Slack volume, how many outside recipients got messages, and large attachment flags"),
        ("ext_pai_events",          f"{BRONZE_SCHEMA}.ext_pai_events",          "6. Social media — public post frequency and mood scores from monitored social accounts"),
        ("ext_geo_events",          f"{BRONZE_SCHEMA}.ext_geo_events",          "7. Location data — employee device positions within buildings and campus with timestamps"),
        ("ext_adjudication_events", f"{BRONZE_SCHEMA}.ext_adjudication_events", "8. Security clearance — clearance status, periodic review flags, and any reinvestigation activity"),
        # Identity directories
        ("ext_badge_registry",      f"{BRONZE_SCHEMA}.ext_badge_registry",      "Badge directory — links each physical access badge to the employee it belongs to"),
        ("ext_asset_assignment",    f"{BRONZE_SCHEMA}.ext_asset_assignment",    "Computer directory — tracks which employee uses which computer and when assignments changed"),
        ("ext_directory",           f"{BRONZE_SCHEMA}.ext_directory",           "Contact directory — maps employee email addresses and messaging handles to their HR record"),
        ("ext_social_handle_map",   f"{BRONZE_SCHEMA}.ext_social_handle_map",   "Social identity — links public social media accounts to employee HR records"),
        # OSINT external feeds (5 streams)
        ("ext_raw_tweets",          f"{BRONZE_SCHEMA}.ext_raw_tweets",          "Twitter/X — public posts from monitored social accounts, including text, sentiment, and engagement"),
        ("ext_raw_instagram_posts", f"{BRONZE_SCHEMA}.ext_raw_instagram_posts", "Instagram — public posts and location check-ins from monitored social accounts"),
        ("ext_raw_lifestyle_signals",f"{BRONZE_SCHEMA}.ext_raw_lifestyle_signals","Lifestyle signals — public purchases, luxury events, and spending patterns from social and public records"),
        ("ext_raw_financial_stress", f"{BRONZE_SCHEMA}.ext_raw_financial_stress", "Financial stress — public court filings, liens, and judgments matched to employee records by name"),
        ("ext_raw_darkweb_signals",  f"{BRONZE_SCHEMA}.ext_raw_darkweb_signals",  "Dark web alerts — employee credentials and personal information detected in breach databases"),
    ]
    unions = "\n    UNION ALL\n    ".join(
        f"SELECT '{name}' AS source_name, '{desc}' AS description, COUNT(*)::INT AS record_count FROM {table}"
        for name, table, desc in rows
    )
    return f"SELECT source_name, description, record_count FROM (\n    {unions}\n) t ORDER BY source_name"


def _silver_sql() -> str:
    rows = [
        # Internal Silver domains
        ("sv_hris",              f"{SILVER_SCHEMA}.sv_hris",              "Employee master — every employee's full HR profile: department, role, clearance, and employment dates"),
        ("sv_pacs",              f"{SILVER_SCHEMA}.sv_pacs",              "Access events — each badge swipe linked to the employee, with after-hours and weekend flags"),
        ("sv_network",           f"{SILVER_SCHEMA}.sv_network",           "Network sessions — all computer and VPN activity linked to the employee who used it"),
        ("sv_dlp",               f"{SILVER_SCHEMA}.sv_dlp",               "File activity — USB copies, cloud uploads, and print events linked to the responsible employee"),
        ("sv_comms",             f"{SILVER_SCHEMA}.sv_comms",             "Messages — email and Slack events linked to each employee, with external contact and attachment flags"),
        ("sv_pai",               f"{SILVER_SCHEMA}.sv_pai",               "Social sentiment — daily mood scores and emotional tags from public social accounts, linked to employees"),
        ("sv_geo",               f"{SILVER_SCHEMA}.sv_geo",               "Location records — device positions on campus linked to each employee by badge"),
        ("sv_adjudication",      f"{SILVER_SCHEMA}.sv_adjudication",      "Clearance history — security status events and reinvestigation flags linked to each employee"),
        ("sv_unresolved_events", f"{SILVER_SCHEMA}.sv_unresolved_events", "Unmatched records — events that could not be linked to a known employee (audit trail)"),
        # OSINT Silver domains
        ("silver_geo_anomalies",        f"{SILVER_SCHEMA}.silver_geo_anomalies",        "Location anomalies — Instagram check-ins flagged as sensitive sites or unusual travel patterns"),
        ("silver_lifestyle_incongruity", f"{SILVER_SCHEMA}.silver_lifestyle_incongruity", "Lifestyle flags — purchases or activities inconsistent with the employee's compensation level"),
        ("silver_financial_stress",      f"{SILVER_SCHEMA}.silver_financial_stress",      "Financial stress records — public court filings, liens, and eviction notices linked to employees"),
        ("silver_darkweb_signals",       f"{SILVER_SCHEMA}.silver_darkweb_signals",       "Dark web matches — employee email or social credentials detected in breach data sources"),
    ]
    unions = "\n    UNION ALL\n    ".join(
        f"SELECT '{name}' AS table_name, '{desc}' AS description, COUNT(*)::INT AS record_count FROM {table}"
        for name, table, desc in rows
    )
    return f"SELECT table_name, description, record_count FROM (\n    {unions}\n) t ORDER BY table_name"


def _gold_sql() -> str:
    rows = [
        # Internal behavioral scoring
        ("employee_risk_features", f"{GOLD_SCHEMA}.employee_risk_features", "Behavioral risk scores — 7-day rolling anomaly score, risk tier (HIGH/MEDIUM/LOW), and 13 derived signals per employee per week"),
        ("employee_features",      f"{GOLD_SCHEMA}.employee_features",      "ML input — normalized numerical feature vectors used as input to the clustering algorithm"),
        ("gd_kmeans_output",       f"{GOLD_SCHEMA}.gd_kmeans_output",       "Peer-group model — 5 behavioral peer clusters learned from the full employee population by the ML engine"),
        ("gd_scored",              f"{GOLD_SCHEMA}.gd_scored",              "Cluster assignments — each employee's distance from their peer group (the raw anomaly signal before scoring)"),
        # OSINT Gold weekly risk streams
        ("gold_twitter_risk",          f"{GOLD_SCHEMA}.gold_twitter_risk",          "Twitter risk — weekly sentiment trend and emotional signal risk score per employee"),
        ("gold_location_risk",         f"{GOLD_SCHEMA}.gold_location_risk",         "Location risk — weekly count of sensitive location visits and travel anomaly score per employee"),
        ("gold_lifestyle_risk",        f"{GOLD_SCHEMA}.gold_lifestyle_risk",         "Lifestyle risk — weekly unexplained spending and luxury activity risk score per employee"),
        ("gold_financial_stress_risk", f"{GOLD_SCHEMA}.gold_financial_stress_risk", "Financial stress risk — weekly public filing count and cumulative financial pressure score per employee"),
        ("gold_darkweb_risk",          f"{GOLD_SCHEMA}.gold_darkweb_risk",          "Dark web risk — weekly breach detection count and severity-weighted risk score per employee"),
        ("gold_composite_risk",        f"{GOLD_SCHEMA}.gold_composite_risk",         "Composite risk — final fused score across all 6 behavioral streams with risk tier (LOW/MEDIUM/HIGH/CRITICAL) and recommended action"),
    ]
    unions = "\n    UNION ALL\n    ".join(
        f"SELECT '{name}' AS table_name, '{desc}' AS description, COUNT(*)::INT AS record_count FROM {table}"
        for name, table, desc in rows
    )
    return f"SELECT table_name, description, record_count FROM (\n    {unions}\n) t ORDER BY table_name"


def setup_datasets(client: SupersetClient, db_id: int) -> dict[str, int]:
    datasets = {}
    for name, sql in [
        ("bronze_catalog", _bronze_sql()),
        ("silver_catalog", _silver_sql()),
        ("gold_catalog",   _gold_sql()),
    ]:
        result = client.post("/api/v1/dataset/", {
            "database": db_id,
            "table_name": name,
            "sql": sql,
        })
        datasets[name] = result["id"]
        logger.info("Created dataset: %s (id=%d)", name, result["id"])
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
        "row_limit": 20,
        "order_desc": False,
        "server_pagination": False,
        "align_pn": False,
        "color_pn": False,
        "show_totals": False,
        "conditional_formatting": [],
    }
    query_context = {
        "datasource": {"id": ds_id, "type": "table"},
        "force": False,
        "queries": [{
            "metrics": [],
            "filters": [],
            "row_limit": 20,
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
