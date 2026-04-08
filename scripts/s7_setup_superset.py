"""
s7_setup_superset.py — Automated Superset dashboard setup for Sentinel-TDI.

Creates via the Superset REST API (idempotent — safe to re-run):
  1. Greenplum database connection
  2. Datasets  — Gold table, Silver resolution summary, pipeline audit
  3. Charts    — scorecards, pie, bar, tables
  4. Dashboard — Sentinel TDI: Insider Threat Detection

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

GOLD_SCHEMA   = "insider_threat_gold"
SILVER_SCHEMA = "insider_threat_silver"
BRONZE_SCHEMA = "insider_threat_bronze"

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
        resp.raise_for_status()
        return resp.json()

    def find_by_name(self, path: str, col: str, value: str) -> dict | None:
        """Return first resource matching col==value, or None."""
        q = json.dumps({"filters": [{"col": col, "opr": "eq", "value": value}]})
        try:
            data = self.get(path, params={"q": q})
            results = data.get("result", [])
            return results[0] if results else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# 1. Database
# ---------------------------------------------------------------------------

def setup_database(client: SupersetClient) -> int:
    """Register Greenplum as a Superset database, return its id."""
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
    db_id = result["id"]
    logger.info("Created database: %s (id=%d)", DB_DISPLAY_NAME, db_id)
    return db_id


# ---------------------------------------------------------------------------
# 2. Datasets
# ---------------------------------------------------------------------------

_SILVER_RESOLUTION_SQL = """
SELECT domain, identity_resolution_status, COUNT(*) AS row_count
FROM (
    SELECT 'hris'          AS domain, identity_resolution_status FROM insider_threat_silver.sv_hris
    UNION ALL
    SELECT 'pacs',         identity_resolution_status FROM insider_threat_silver.sv_pacs
    UNION ALL
    SELECT 'network',      identity_resolution_status FROM insider_threat_silver.sv_network
    UNION ALL
    SELECT 'dlp',          identity_resolution_status FROM insider_threat_silver.sv_dlp
    UNION ALL
    SELECT 'comms',        identity_resolution_status FROM insider_threat_silver.sv_comms
    UNION ALL
    SELECT 'pai',          identity_resolution_status FROM insider_threat_silver.sv_pai
    UNION ALL
    SELECT 'geo',          identity_resolution_status FROM insider_threat_silver.sv_geo
    UNION ALL
    SELECT 'adjudication', identity_resolution_status FROM insider_threat_silver.sv_adjudication
) all_domains
GROUP BY domain, identity_resolution_status
ORDER BY domain
"""

_GOLD_LATEST_SQL = """
SELECT *
FROM insider_threat_gold.employee_risk_features
WHERE window_end_date = (
    SELECT MAX(window_end_date) FROM insider_threat_gold.employee_risk_features
)
ORDER BY anomaly_score DESC
"""


def setup_datasets(client: SupersetClient, db_id: int) -> dict[str, int]:
    """Create all datasets, return name → dataset_id mapping."""
    datasets: dict[str, int] = {}

    # Table-backed datasets
    for table_name, schema in [
        ("employee_risk_features", GOLD_SCHEMA),
        ("pipeline_runs",          BRONZE_SCHEMA),
    ]:
        datasets[table_name] = _get_or_create_table_dataset(client, db_id, table_name, schema)

    # Virtual (SQL) datasets
    for name, sql in [
        ("silver_resolution_summary", _SILVER_RESOLUTION_SQL),
        ("gold_latest_window",        _GOLD_LATEST_SQL),
    ]:
        datasets[name] = _get_or_create_virtual_dataset(client, db_id, name, sql)

    return datasets


def _get_or_create_table_dataset(
    client: SupersetClient, db_id: int, table_name: str, schema: str
) -> int:
    existing = client.find_by_name("/api/v1/dataset/", "table_name", table_name)
    if existing:
        logger.info("Dataset exists: %s (id=%d)", table_name, existing["id"])
        return existing["id"]
    result = client.post("/api/v1/dataset/", {
        "database": db_id,
        "table_name": table_name,
        "schema": schema,
    })
    logger.info("Created table dataset: %s (id=%d)", table_name, result["id"])
    return result["id"]


def _get_or_create_virtual_dataset(
    client: SupersetClient, db_id: int, name: str, sql: str
) -> int:
    existing = client.find_by_name("/api/v1/dataset/", "table_name", name)
    if existing:
        logger.info("Dataset exists: %s (id=%d)", name, existing["id"])
        return existing["id"]
    result = client.post("/api/v1/dataset/", {
        "database": db_id,
        "table_name": name,
        "sql": sql,
    })
    logger.info("Created virtual dataset: %s (id=%d)", name, result["id"])
    return result["id"]


# ---------------------------------------------------------------------------
# 3. Charts
# ---------------------------------------------------------------------------

def _metric(sql: str, label: str) -> dict:
    return {
        "expressionType": "SQL",
        "sqlExpression": sql,
        "label": label,
        "hasCustomLabel": True,
    }


def _base_params(viz_type: str, ds_id: int, ds_type: str = "table") -> dict:
    """Common params that every chart needs in Superset 3.x."""
    return {
        "viz_type": viz_type,
        "datasource": f"{ds_id}__{ds_type}",
        "adhoc_filters": [],
        "time_range": "No filter",
    }


def _query_context(ds_id: int, metrics: list[dict], columns: list[str] | None = None,
                   groupby: list[str] | None = None, row_limit: int = 1000,
                   ds_type: str = "table") -> str:
    """Build the query_context JSON string Superset 3.x needs to render charts."""
    query: dict = {
        "metrics": metrics,
        "filters": [],
        "row_limit": row_limit,
        "orderby": [],
        "extras": {},
        "time_range": "No filter",
        "columns": columns or [],
        "groupby": groupby or [],
    }
    ctx = {
        "datasource": {"id": ds_id, "type": ds_type},
        "force": False,
        "queries": [query],
        "result_format": "json",
        "result_type": "full",
    }
    return json.dumps(ctx)


def _chart_specs(datasets: dict[str, int]) -> list[dict]:
    gold_ds   = datasets["employee_risk_features"]
    latest_ds = datasets["gold_latest_window"]
    runs_ds   = datasets["pipeline_runs"]
    silver_ds = datasets["silver_resolution_summary"]

    m_employees   = _metric("COUNT(DISTINCT employee_id)", "Employees Scored")
    m_high_risk   = _metric("COUNT(DISTINCT CASE WHEN anomaly_tier = 'HIGH' THEN employee_id END)", "HIGH Risk")
    m_domains     = _metric("COUNT(DISTINCT domain)", "Domains Loaded")
    m_stage_runs  = _metric("COUNT(*)", "Stage Runs")
    m_emp_count   = _metric("COUNT(DISTINCT employee_id)", "Employees")
    m_records     = _metric("SUM(row_count)", "Records")

    return [
        # ── Row 1: Scorecards ───────────────────────────────────────────────
        {
            "slice_name": "Employees Scored",
            "viz_type":   "big_number_total",
            "datasource_id": gold_ds,
            "params": json.dumps({
                **_base_params("big_number_total", gold_ds),
                "metric": m_employees,
                "subheader": "total employees with anomaly scores",
                "y_axis_format": "SMART_NUMBER",
            }),
            "query_context": _query_context(gold_ds, [m_employees], row_limit=1),
        },
        {
            "slice_name": "HIGH Risk Employees",
            "viz_type":   "big_number_total",
            "datasource_id": gold_ds,
            "params": json.dumps({
                **_base_params("big_number_total", gold_ds),
                "metric": m_high_risk,
                "subheader": "anomaly tier HIGH — top 5% by score",
                "y_axis_format": "SMART_NUMBER",
            }),
            "query_context": _query_context(gold_ds, [m_high_risk], row_limit=1),
        },
        {
            "slice_name": "Silver Domains Loaded",
            "viz_type":   "big_number_total",
            "datasource_id": silver_ds,
            "params": json.dumps({
                **_base_params("big_number_total", silver_ds),
                "metric": m_domains,
                "subheader": "Silver domains with resolved records",
                "y_axis_format": "SMART_NUMBER",
            }),
            "query_context": _query_context(silver_ds, [m_domains], row_limit=1),
        },
        {
            "slice_name": "Pipeline Stages Run",
            "viz_type":   "big_number_total",
            "datasource_id": runs_ds,
            "params": json.dumps({
                **_base_params("big_number_total", runs_ds),
                "metric": m_stage_runs,
                "subheader": "pipeline stage executions logged",
                "y_axis_format": "SMART_NUMBER",
            }),
            "query_context": _query_context(runs_ds, [m_stage_runs], row_limit=1),
        },

        # ── Row 2: Gold anomaly distribution ───────────────────────────────
        {
            "slice_name": "Anomaly Tier Distribution",
            "viz_type":   "echarts_pie",
            "datasource_id": latest_ds,
            "params": json.dumps({
                **_base_params("echarts_pie", latest_ds),
                "groupby": ["anomaly_tier"],
                "metric": m_emp_count,
                "innerRadius": 30,
                "outerRadius": 70,
                "labelsOutside": True,
                "show_legend": True,
            }),
            "query_context": _query_context(latest_ds, [m_emp_count],
                                            groupby=["anomaly_tier"]),
        },
        {
            "slice_name": "Top 25 Highest Risk Employees",
            "viz_type":   "table",
            "datasource_id": latest_ds,
            "params": json.dumps({
                **_base_params("table", latest_ds),
                "query_mode": "raw",
                "columns": [
                    "employee_id", "anomaly_tier", "anomaly_score",
                    "anomaly_percentile", "cross_domain_anomaly_count",
                    "cluster_id", "window_end_date",
                ],
                "metrics": [],
                "row_limit": 25,
                "order_desc": True,
                "server_pagination": False,
            }),
            "query_context": _query_context(
                latest_ds, [],
                columns=["employee_id", "anomaly_tier", "anomaly_score",
                         "anomaly_percentile", "cross_domain_anomaly_count",
                         "cluster_id", "window_end_date"],
                row_limit=25,
            ),
        },

        # ── Row 3: Silver identity resolution ──────────────────────────────
        {
            "slice_name": "Silver Identity Resolution by Domain",
            "viz_type":   "echarts_bar",
            "datasource_id": silver_ds,
            "params": json.dumps({
                **_base_params("echarts_bar", silver_ds),
                "x_axis": "domain",
                "groupby": ["identity_resolution_status"],
                "metrics": [m_records],
                "stack": True,
                "show_legend": True,
                "show_value": True,
                "orientation": "vertical",
                "x_axis_title": "Source Domain",
                "y_axis_title": "Record Count",
            }),
            "query_context": _query_context(
                silver_ds, [m_records],
                groupby=["domain", "identity_resolution_status"],
            ),
        },

        # ── Row 4: Pipeline lineage audit ──────────────────────────────────
        {
            "slice_name": "Pipeline Run Audit",
            "viz_type":   "table",
            "datasource_id": runs_ds,
            "params": json.dumps({
                **_base_params("table", runs_ds),
                "query_mode": "raw",
                "columns": [
                    "stage_name", "status", "rows_in", "rows_out",
                    "duration_seconds", "started_at", "completed_at",
                ],
                "metrics": [],
                "row_limit": 50,
                "order_desc": True,
                "server_pagination": False,
            }),
            "query_context": _query_context(
                runs_ds, [],
                columns=["stage_name", "status", "rows_in", "rows_out",
                         "duration_seconds", "started_at", "completed_at"],
                row_limit=50,
            ),
        },
    ]


def setup_charts(client: SupersetClient, datasets: dict[str, int]) -> list[int]:
    """Create or update all charts, return list of chart ids."""
    chart_ids: list[int] = []
    for spec in _chart_specs(datasets):
        chart_payload = {
            "slice_name":      spec["slice_name"],
            "viz_type":        spec["viz_type"],
            "datasource_id":   spec["datasource_id"],
            "datasource_type": "table",
            "params":          spec["params"],
            "query_context":   spec["query_context"],
        }
        existing = client.find_by_name("/api/v1/chart/", "slice_name", spec["slice_name"])
        if existing:
            cid = existing["id"]
            client.put(f"/api/v1/chart/{cid}", chart_payload)
            logger.info("Updated chart: %s (id=%d)", spec["slice_name"], cid)
            chart_ids.append(cid)
        else:
            result = client.post("/api/v1/chart/", chart_payload)
            logger.info("Created chart: %s (id=%d)", spec["slice_name"], result["id"])
            chart_ids.append(result["id"])
    return chart_ids


# ---------------------------------------------------------------------------
# 4. Dashboard layout
# ---------------------------------------------------------------------------

def _build_position_json(chart_ids: list[int]) -> str:
    """
    Build Superset dashboard position_json.
    Grid is 24 columns wide. Heights are in units (~10px each).

    Row 1 — 4 scorecards          (width=6, height=18 each)
    Row 2 — pie + top-25 table    (width=8 + 16, height=40)
    Row 3 — resolution bar chart  (width=24, height=36)
    Row 4 — pipeline audit table  (width=24, height=36)
    """
    rows = [
        ("ROW-1", [(0, 6, 18), (1, 6, 18), (2, 6, 18), (3, 6, 18)]),
        ("ROW-2", [(4, 8, 40), (5, 16, 40)]),
        ("ROW-3", [(6, 24, 36)]),
        ("ROW-4", [(7, 24, 36)]),
    ]

    layout: dict[str, Any] = {
        "DASHBOARD_VERSION_KEY": "v2",
        "ROOT_ID": {"type": "ROOT", "id": "ROOT_ID", "children": ["GRID_ID"]},
        "GRID_ID": {
            "type": "GRID", "id": "GRID_ID",
            "children": [r[0] for r in rows],
            "parents": ["ROOT_ID"],
        },
    }

    for row_id, slots in rows:
        node_ids = []
        for chart_idx, width, height in slots:
            node_id = f"CHART-{chart_idx}"
            node_ids.append(node_id)
            layout[node_id] = {
                "type": "CHART", "id": node_id,
                "children": [], "parents": [row_id],
                "meta": {
                    "chartId": chart_ids[chart_idx],
                    "width": width,
                    "height": height,
                },
            }
        layout[row_id] = {
            "type": "ROW", "id": row_id,
            "children": node_ids, "parents": ["GRID_ID"],
            "meta": {"background": "BACKGROUND_TRANSPARENT"},
        }

    return json.dumps(layout)


def setup_dashboard(client: SupersetClient, chart_ids: list[int]) -> int:
    """Create or update the dashboard, return its id."""
    position_json = _build_position_json(chart_ids)
    payload = {
        "dashboard_title": DASHBOARD_TITLE,
        "published": True,
        "position_json": position_json,
    }

    existing = client.find_by_name("/api/v1/dashboard/", "dashboard_title", DASHBOARD_TITLE)
    if existing:
        dash_id = existing["id"]
        client.put(f"/api/v1/dashboard/{dash_id}", payload)
        logger.info("Updated dashboard layout: %s (id=%d)", DASHBOARD_TITLE, dash_id)
    else:
        result = client.post("/api/v1/dashboard/", payload)
        dash_id = result["id"]
        logger.info("Created dashboard: %s (id=%d)", DASHBOARD_TITLE, dash_id)

    # In Superset 3.x, charts are linked to a dashboard by PUTting the dashboard id
    # onto each chart's 'dashboards' field — position_json alone is not enough.
    for cid in chart_ids:
        client.put(f"/api/v1/chart/{cid}", {"dashboards": [dash_id]})
        logger.debug("Linked chart %d → dashboard %d", cid, dash_id)
    logger.info("Linked %d charts to dashboard %d", len(chart_ids), dash_id)

    return dash_id


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> dict:
    """Run the full Superset setup sequence."""
    missing = [v for v in ["SUPERSET_URL", "SUPERSET_USER", "SUPERSET_PASSWORD", "GP_PASSWORD"]
               if not os.getenv(v)]
    if missing:
        logger.error("Missing required env vars: %s", ", ".join(missing))
        sys.exit(1)

    t0 = time.perf_counter()

    client = SupersetClient(SUPERSET_URL, SUPERSET_USER, SUPERSET_PASSWORD)

    logger.info("Step 1/4 — Register Greenplum database")
    db_id = setup_database(client)

    logger.info("Step 2/4 — Create datasets")
    datasets = setup_datasets(client, db_id)

    logger.info("Step 3/4 — Create charts")
    chart_ids = setup_charts(client, datasets)

    logger.info("Step 4/4 — Create dashboard")
    dash_id = setup_dashboard(client, chart_ids)

    duration = time.perf_counter() - t0
    url = f"{SUPERSET_URL}/superset/dashboard/{dash_id}/"
    logger.info("Done in %.1fs", duration)
    print(f"\nDashboard ready: {url}\n")

    return {"status": "success", "dashboard_id": dash_id, "dashboard_url": url}


if __name__ == "__main__":
    run()
