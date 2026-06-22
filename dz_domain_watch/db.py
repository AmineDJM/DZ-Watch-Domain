"""SQLite database layer for DZ Domain Watch.

Uses WAL mode to allow concurrent reads from Streamlit while the collector writes.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

from .models import CertEvent

DB_PATH = Path(__file__).parent.parent / "data" / "dz_watch.db"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cert_events (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain                  TEXT NOT NULL,
    raw_domain              TEXT,
    registered_domain       TEXT,
    tld                     TEXT,
    issuer                  TEXT,
    seen_utc                TEXT,
    not_before_utc          TEXT,
    not_after_utc           TEXT,
    source                  TEXT,
    cert_link               TEXT,
    fingerprint             TEXT,
    is_wildcard             INTEGER DEFAULT 0,
    risk_score              INTEGER DEFAULT 0,
    risk_level              TEXT DEFAULT 'low',
    matched_keywords        TEXT,
    matched_brands          TEXT,
    matched_suspicious_words TEXT,
    reasons                 TEXT,
    inserted_at_utc         TEXT,
    UNIQUE(domain, fingerprint)
);
"""

CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_cert_events_risk_score ON cert_events(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cert_events_seen_utc   ON cert_events(seen_utc DESC);
CREATE INDEX IF NOT EXISTS idx_cert_events_domain     ON cert_events(domain);
"""


def get_db_path() -> Path:
    """Return the database file path, ensuring the parent directory exists."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return DB_PATH


@contextmanager
def get_connection(db_path: Optional[Path] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that yields a SQLite connection with WAL mode enabled."""
    path = db_path or get_db_path()
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[Path] = None) -> None:
    """Create tables and indexes if they don't already exist."""
    with get_connection(db_path) as conn:
        conn.executescript(CREATE_TABLE_SQL)
        for stmt in CREATE_INDEX_SQL.strip().split("\n"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(stmt)
    print(f"[DB] Database initialized at {db_path or get_db_path()}")


def insert_event(event: CertEvent, db_path: Optional[Path] = None) -> bool:
    """Insert a CertEvent into the database.

    Returns True if inserted, False if duplicate (UNIQUE constraint).
    """
    now = datetime.now(tz=timezone.utc).isoformat()
    sql = """
    INSERT OR IGNORE INTO cert_events (
        domain, raw_domain, registered_domain, tld,
        issuer, seen_utc, not_before_utc, not_after_utc,
        source, cert_link, fingerprint, is_wildcard,
        risk_score, risk_level,
        matched_keywords, matched_brands, matched_suspicious_words,
        reasons, inserted_at_utc
    ) VALUES (
        :domain, :raw_domain, :registered_domain, :tld,
        :issuer, :seen_utc, :not_before_utc, :not_after_utc,
        :source, :cert_link, :fingerprint, :is_wildcard,
        :risk_score, :risk_level,
        :matched_keywords, :matched_brands, :matched_suspicious_words,
        :reasons, :inserted_at_utc
    )
    """
    params = {
        "domain": event.domain,
        "raw_domain": event.raw_domain,
        "registered_domain": event.registered_domain,
        "tld": event.tld,
        "issuer": event.issuer,
        "seen_utc": event.seen_utc,
        "not_before_utc": event.not_before_utc,
        "not_after_utc": event.not_after_utc,
        "source": event.source,
        "cert_link": event.cert_link,
        "fingerprint": event.fingerprint,
        "is_wildcard": int(event.is_wildcard),
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "matched_keywords": json.dumps(event.matched_keywords, ensure_ascii=False),
        "matched_brands": json.dumps(event.matched_brands, ensure_ascii=False),
        "matched_suspicious_words": json.dumps(
            event.matched_suspicious_words, ensure_ascii=False
        ),
        "reasons": json.dumps(event.reasons, ensure_ascii=False),
        "inserted_at_utc": now,
    }
    with get_connection(db_path) as conn:
        cursor = conn.execute(sql, params)
        return cursor.rowcount > 0


def fetch_events(
    min_score: int = 0,
    risk_level: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 1000,
    db_path: Optional[Path] = None,
) -> list[dict]:
    """Fetch events from the database with optional filters."""
    conditions = ["risk_score >= :min_score"]
    params: dict = {"min_score": min_score, "limit": limit}

    if risk_level and risk_level != "all":
        conditions.append("risk_level = :risk_level")
        params["risk_level"] = risk_level

    if search:
        conditions.append("(domain LIKE :search OR issuer LIKE :search OR reasons LIKE :search)")
        params["search"] = f"%{search}%"

    where = " AND ".join(conditions)
    sql = f"""
    SELECT * FROM cert_events
    WHERE {where}
    ORDER BY seen_utc DESC
    LIMIT :limit
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def fetch_stats(db_path: Optional[Path] = None) -> dict:
    """Return aggregate statistics for the KPI panel."""
    sql = """
    SELECT
        COUNT(*)                                        AS total_events,
        COUNT(DISTINCT domain)                         AS unique_domains,
        SUM(CASE WHEN risk_level IN ('high','critical') THEN 1 ELSE 0 END) AS high_critical,
        MAX(risk_score)                                AS max_score,
        MAX(seen_utc)                                  AS last_seen,
        SUM(CASE WHEN seen_utc >= datetime('now', '-1 hour') THEN 1 ELSE 0 END) AS last_hour
    FROM cert_events
    """
    with get_connection(db_path) as conn:
        row = conn.execute(sql).fetchone()
    return dict(row) if row else {}
