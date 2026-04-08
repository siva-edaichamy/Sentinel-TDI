"""
db.py — Shared Greenplum connection factory for all pipeline scripts.

All scripts import get_connection() or get_pool() from here.
Credentials are loaded from environment variables (populated via .env).
"""

import logging
import os
from contextlib import contextmanager
from pathlib import Path

import psycopg2
import psycopg2.pool
from dotenv import load_dotenv

# Load .env from project root (two levels up from this file)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

logger = logging.getLogger(__name__)

_ENV_PROFILES: dict[str, dict] = {
    "local": {
        "host": os.getenv("GP_HOST", "localhost"),
        "port": int(os.getenv("GP_PORT", 5432)),
        "dbname": os.getenv("GP_DB", "gpadmin"),
        "user": os.getenv("GP_USER", "gpadmin"),
        "password": os.getenv("GP_PASSWORD", ""),
    },
    "dev": {
        "host": os.getenv("GP_HOST_DEV", os.getenv("GP_HOST", "localhost")),
        "port": int(os.getenv("GP_PORT_DEV", os.getenv("GP_PORT", 5432))),
        "dbname": os.getenv("GP_DB_DEV", os.getenv("GP_DB", "gpadmin")),
        "user": os.getenv("GP_USER_DEV", os.getenv("GP_USER", "gpadmin")),
        "password": os.getenv("GP_PASSWORD_DEV", os.getenv("GP_PASSWORD", "")),
    },
    "prod": {
        "host": os.getenv("GP_HOST_PROD", os.getenv("GP_HOST", "localhost")),
        "port": int(os.getenv("GP_PORT_PROD", os.getenv("GP_PORT", 5432))),
        "dbname": os.getenv("GP_DB_PROD", os.getenv("GP_DB", "gpadmin")),
        "user": os.getenv("GP_USER_PROD", os.getenv("GP_USER", "gpadmin")),
        "password": os.getenv("GP_PASSWORD_PROD", os.getenv("GP_PASSWORD", "")),
    },
}

# Module-level pool cache keyed by env name
_pools: dict[str, psycopg2.pool.ThreadedConnectionPool] = {}


def _dsn(env: str) -> dict:
    """Return the connection kwargs for the given environment profile."""
    if env not in _ENV_PROFILES:
        raise ValueError(f"Unknown env '{env}'. Must be one of: {list(_ENV_PROFILES)}")
    return _ENV_PROFILES[env]


def get_pool(env: str = "local", minconn: int = 1, maxconn: int = 5) -> psycopg2.pool.ThreadedConnectionPool:
    """Return (creating if needed) a threaded connection pool for the given env."""
    if env not in _pools:
        dsn = _dsn(env)
        logger.info("Creating connection pool for env=%s host=%s db=%s", env, dsn["host"], dsn["dbname"])
        _pools[env] = psycopg2.pool.ThreadedConnectionPool(minconn, maxconn, **dsn)
    return _pools[env]


@contextmanager
def get_connection(env: str = "local"):
    """
    Context manager that yields a psycopg2 connection from the pool.

    Usage:
        with get_connection(env) as conn:
            with conn.cursor() as cur:
                cur.execute(...)
            conn.commit()
    """
    pool = get_pool(env)
    conn = pool.getconn()
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def close_all_pools() -> None:
    """Close all open connection pools. Call at pipeline shutdown."""
    for env, pool in _pools.items():
        logger.debug("Closing connection pool for env=%s", env)
        pool.closeall()
    _pools.clear()


def test_connection(env: str = "local") -> bool:
    """
    Smoke-test the connection. Returns True on success, raises on failure.
    Agents call this at startup to fail fast before doing any work.
    """
    with get_connection(env) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version();")
            version = cur.fetchone()[0]
    logger.info("Greenplum connection OK [env=%s]: %s", env, version)
    return True
