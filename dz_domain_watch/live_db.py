"""Persistent storage for live domain reachability status.

The live checker writes here continuously; the Streamlit dashboard reads from
here. This decouples the (slow) HTTP checks from the (fast, auto-refreshing) UI
so results survive Streamlit reruns.
"""

from pathlib import Path
from typing import Optional

from .db import get_connection

CREATE_LIVE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS live_status (
    domain         TEXT PRIMARY KEY,
    is_live        INTEGER DEFAULT 0,
    status_code    INTEGER,
    server         TEXT,
    redirect_url   TEXT,
    checked_at     TEXT,
    error          TEXT
);
"""

CREATE_LIVE_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_live_status_is_live ON live_status(is_live);"
)


def init_live_db(db_path: Optional[Path] = None) -> None:
    with get_connection(db_path) as conn:
        conn.execute(CREATE_LIVE_TABLE_SQL)
        conn.execute(CREATE_LIVE_INDEX_SQL)


def upsert_live_status(result: dict, db_path: Optional[Path] = None) -> None:
    sql = """
    INSERT INTO live_status (domain, is_live, status_code, server, redirect_url, checked_at, error)
    VALUES (:domain, :is_live, :status_code, :server, :redirect_url, :checked_at, :error)
    ON CONFLICT(domain) DO UPDATE SET
        is_live=excluded.is_live,
        status_code=excluded.status_code,
        server=excluded.server,
        redirect_url=excluded.redirect_url,
        checked_at=excluded.checked_at,
        error=excluded.error
    """
    params = {
        "domain": result.get("domain"),
        "is_live": int(bool(result.get("is_live"))),
        "status_code": result.get("status_code"),
        "server": result.get("server") or "",
        "redirect_url": result.get("redirect_url") or "",
        "checked_at": result.get("checked_at"),
        "error": result.get("error") or "",
    }
    with get_connection(db_path) as conn:
        conn.execute(sql, params)


def fetch_live_status_map(db_path: Optional[Path] = None) -> dict[str, dict]:
    """Return {domain: status_row} for every domain checked so far."""
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT * FROM live_status").fetchall()
    return {row["domain"]: dict(row) for row in rows}


def fetch_live_stats(db_path: Optional[Path] = None) -> dict:
    sql = """
    SELECT
        COUNT(*)                                         AS total_checked,
        SUM(CASE WHEN is_live=1 THEN 1 ELSE 0 END)       AS total_live,
        MAX(checked_at)                                  AS last_check
    FROM live_status
    """
    with get_connection(db_path) as conn:
        row = conn.execute(sql).fetchone()
    return dict(row) if row else {}
