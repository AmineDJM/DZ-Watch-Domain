"""Data models for DZ Domain Watch."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CertEvent:
    """Represents a parsed certificate transparency event."""

    domain: str
    raw_domain: str
    registered_domain: str
    tld: str
    issuer: str
    seen_utc: str
    not_before_utc: Optional[str]
    not_after_utc: Optional[str]
    source: str
    cert_link: Optional[str]
    fingerprint: Optional[str]
    is_wildcard: bool

    # Scoring fields (populated after analysis)
    risk_score: int = 0
    risk_level: str = "low"
    matched_keywords: list = field(default_factory=list)
    matched_brands: list = field(default_factory=list)
    matched_suspicious_words: list = field(default_factory=list)
    reasons: list = field(default_factory=list)


@dataclass
class ScoreResult:
    """Result of the risk scoring analysis."""

    risk_score: int
    risk_level: str
    matched_keywords: list
    matched_brands: list
    matched_suspicious_words: list
    reasons: list
