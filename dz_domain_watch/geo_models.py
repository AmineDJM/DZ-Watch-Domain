"""Geo dataclasses for DZ Domain Watch Geo Intelligence War Room."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class GeoPoint:
    domain: str
    ip: str
    lat: float
    lon: float
    country: str
    country_code: str
    city: str
    asn: str
    org: str
    campaign: str
    risk_score: int
    risk_level: str
    seen_utc: str
    registered_domain: str = ""
    isp: str = ""
    hosting_provider: str = ""


@dataclass
class GeoArc:
    domain: str
    src_lat: float
    src_lon: float
    src_city: str
    dst_lat: float
    dst_lon: float
    dst_city: str
    campaign: str
    risk_score: int
    risk_level: str


@dataclass
class GeoCluster:
    campaign: str
    count: int
    countries: list[str]
    risk_max: int
    risk_level: str
    center_lat: float
    center_lon: float
    domains: list[str] = field(default_factory=list)
