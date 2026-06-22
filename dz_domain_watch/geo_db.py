"""Geo database layer — tables and queries for the Geo Intelligence War Room."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

from .db import get_db_path, get_connection

CREATE_GEO_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS geo_points (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    domain            TEXT NOT NULL,
    registered_domain TEXT,
    ip                TEXT,
    lat               REAL,
    lon               REAL,
    country           TEXT,
    country_code      TEXT,
    city              TEXT,
    asn               TEXT,
    org               TEXT,
    isp               TEXT,
    hosting_provider  TEXT,
    campaign          TEXT,
    risk_score        INTEGER DEFAULT 0,
    risk_level        TEXT DEFAULT 'low',
    seen_utc          TEXT,
    inserted_at_utc   TEXT,
    UNIQUE(domain, ip)
);

CREATE TABLE IF NOT EXISTS geo_arcs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    src_lat      REAL,
    src_lon      REAL,
    src_city     TEXT,
    dst_lat      REAL,
    dst_lon      REAL,
    dst_city     TEXT,
    campaign     TEXT,
    risk_score   INTEGER DEFAULT 0,
    risk_level   TEXT DEFAULT 'low',
    seen_utc     TEXT,
    UNIQUE(domain, src_city, dst_city)
);

CREATE TABLE IF NOT EXISTS geo_clusters (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign     TEXT NOT NULL UNIQUE,
    count        INTEGER DEFAULT 0,
    countries    TEXT,
    risk_max     INTEGER DEFAULT 0,
    risk_level   TEXT DEFAULT 'low',
    center_lat   REAL,
    center_lon   REAL,
    domains      TEXT,
    updated_at   TEXT
);
"""

CREATE_GEO_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_geo_points_campaign   ON geo_points(campaign);
CREATE INDEX IF NOT EXISTS idx_geo_points_risk_score ON geo_points(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_geo_arcs_campaign     ON geo_arcs(campaign);
"""


def init_geo_db(db_path: Optional[Path] = None) -> None:
    """Create geo tables if they don't exist."""
    with get_connection(db_path) as conn:
        conn.executescript(CREATE_GEO_TABLES_SQL)
        for stmt in CREATE_GEO_INDEXES_SQL.strip().split("\n"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(stmt)


def insert_geo_point(point: dict, db_path: Optional[Path] = None) -> bool:
    sql = """
    INSERT OR IGNORE INTO geo_points (
        domain, registered_domain, ip, lat, lon, country, country_code,
        city, asn, org, isp, hosting_provider, campaign,
        risk_score, risk_level, seen_utc, inserted_at_utc
    ) VALUES (
        :domain, :registered_domain, :ip, :lat, :lon, :country, :country_code,
        :city, :asn, :org, :isp, :hosting_provider, :campaign,
        :risk_score, :risk_level, :seen_utc, :inserted_at_utc
    )
    """
    with get_connection(db_path) as conn:
        cur = conn.execute(sql, point)
        return cur.rowcount > 0


def insert_geo_arc(arc: dict, db_path: Optional[Path] = None) -> bool:
    sql = """
    INSERT OR IGNORE INTO geo_arcs (
        domain, src_lat, src_lon, src_city,
        dst_lat, dst_lon, dst_city,
        campaign, risk_score, risk_level, seen_utc
    ) VALUES (
        :domain, :src_lat, :src_lon, :src_city,
        :dst_lat, :dst_lon, :dst_city,
        :campaign, :risk_score, :risk_level, :seen_utc
    )
    """
    with get_connection(db_path) as conn:
        cur = conn.execute(sql, arc)
        return cur.rowcount > 0


def upsert_geo_cluster(cluster: dict, db_path: Optional[Path] = None) -> None:
    sql = """
    INSERT INTO geo_clusters (campaign, count, countries, risk_max, risk_level, center_lat, center_lon, domains, updated_at)
    VALUES (:campaign, :count, :countries, :risk_max, :risk_level, :center_lat, :center_lon, :domains, :updated_at)
    ON CONFLICT(campaign) DO UPDATE SET
        count=excluded.count, countries=excluded.countries,
        risk_max=excluded.risk_max, risk_level=excluded.risk_level,
        center_lat=excluded.center_lat, center_lon=excluded.center_lon,
        domains=excluded.domains, updated_at=excluded.updated_at
    """
    with get_connection(db_path) as conn:
        conn.execute(sql, cluster)


def fetch_geo_points(campaign: Optional[str] = None, db_path: Optional[Path] = None) -> list[dict]:
    conditions = ["1=1"]
    params: dict = {}
    if campaign and campaign != "Toutes":
        conditions.append("campaign = :campaign")
        params["campaign"] = campaign
    sql = f"SELECT * FROM geo_points WHERE {' AND '.join(conditions)} ORDER BY risk_score DESC LIMIT 2000"
    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def fetch_geo_arcs(campaign: Optional[str] = None, db_path: Optional[Path] = None) -> list[dict]:
    conditions = ["1=1"]
    params: dict = {}
    if campaign and campaign != "Toutes":
        conditions.append("campaign = :campaign")
        params["campaign"] = campaign
    sql = f"SELECT * FROM geo_arcs WHERE {' AND '.join(conditions)} ORDER BY risk_score DESC LIMIT 1000"
    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def fetch_geo_clusters(db_path: Optional[Path] = None) -> list[dict]:
    sql = "SELECT * FROM geo_clusters ORDER BY risk_max DESC"
    with get_connection(db_path) as conn:
        rows = conn.execute(sql).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        for field in ("countries", "domains"):
            try:
                d[field] = json.loads(d[field]) if d.get(field) else []
            except Exception:
                d[field] = []
        result.append(d)
    return result


def fetch_geo_stats(db_path: Optional[Path] = None) -> dict:
    sql = """
    SELECT
        COUNT(*)                    AS total_ips,
        COUNT(DISTINCT country)     AS countries_count,
        COUNT(DISTINCT campaign)    AS campaigns_count,
        COUNT(DISTINCT hosting_provider) AS providers_count,
        MAX(risk_score)             AS max_score
    FROM geo_points
    """
    with get_connection(db_path) as conn:
        row = conn.execute(sql).fetchone()
    return dict(row) if row else {}


def fetch_campaigns(db_path: Optional[Path] = None) -> list[str]:
    sql = "SELECT DISTINCT campaign FROM geo_points WHERE campaign IS NOT NULL ORDER BY campaign"
    with get_connection(db_path) as conn:
        rows = conn.execute(sql).fetchall()
    return [r[0] for r in rows]
