"""Utility functions for domain parsing and normalization."""

import re
import unicodedata
from typing import Optional

import tldextract


def normalize_domain(domain: str) -> str:
    """Lowercase, strip wildcards and whitespace from a domain string."""
    domain = domain.strip().lower()
    if domain.startswith("*."):
        domain = domain[2:]
    return domain


def is_wildcard(raw_domain: str) -> bool:
    """Return True if the raw domain is a wildcard certificate entry."""
    return raw_domain.strip().startswith("*.")


def extract_parts(domain: str) -> dict:
    """Extract subdomain, domain, suffix from a domain using tldextract.

    Returns a dict with keys: subdomain, domain, suffix, registered_domain, fqdn.
    """
    ext = tldextract.extract(domain)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return {
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "registered_domain": registered,
        "fqdn": domain,
    }


def clean_text_for_matching(text: str) -> str:
    """Remove accents and normalize to ASCII for robust keyword matching."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


def contains_keyword(domain: str, keywords: list[str]) -> list[str]:
    """Return list of keywords found anywhere in the domain string."""
    domain_clean = clean_text_for_matching(domain)
    return [kw for kw in keywords if clean_text_for_matching(kw) in domain_clean]


def parse_timestamp(ts) -> Optional[str]:
    """Safely convert a Unix timestamp or ISO string to UTC ISO format."""
    if ts is None:
        return None
    try:
        from datetime import datetime, timezone

        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        return str(ts)
    except Exception:
        return None


def safe_get(obj: dict, *keys, default=None):
    """Safely traverse nested dict keys, returning default on any miss or error."""
    try:
        for key in keys:
            obj = obj[key]
        return obj
    except (KeyError, TypeError, IndexError):
        return default


def count_hyphens(domain: str) -> int:
    """Count the number of hyphens in the domain (excluding TLD portion)."""
    parts = extract_parts(domain)
    base = parts["domain"] + (f"-{parts['subdomain']}" if parts["subdomain"] else "")
    return base.count("-")


def get_tld(domain: str) -> str:
    """Return the TLD (suffix) of a domain prefixed with a dot."""
    parts = extract_parts(domain)
    suffix = parts["suffix"]
    return f".{suffix}" if suffix else ""
