"""Demo data injection for DZ Domain Watch.

Inserts realistic synthetic certificate events to allow testing the
Streamlit dashboard without waiting for real CertStream matches.
"""

import uuid
from datetime import datetime, timedelta, timezone

from .db import insert_event
from .models import CertEvent
from .scoring import score_domain
from .utils import extract_parts, get_tld, is_wildcard, normalize_domain

_DEMO_DOMAINS = [
    # High-risk: brand + suspicious word combinations
    ("airalgerie-refund-support.com", "Let's Encrypt", False),
    ("baridimob-verification.net", "Let's Encrypt", False),
    ("aadl-inscription-2026.com", "ZeroSSL", False),
    ("poste-dz-login.xyz", "Let's Encrypt", False),
    ("sonatrach-careers.org", "Let's Encrypt", False),
    ("mobilis-secure-update.com", "Let's Encrypt", False),
    ("edahabia-payment-confirm.top", "Let's Encrypt", False),
    ("djezzy-account-verify.xyz", "ZeroSSL", False),
    ("ooredoo-dz-support.online", "Let's Encrypt", False),
    ("bna-algerie-login.site", "Let's Encrypt", False),
    # Medium risk: country keyword only
    ("algerie-visa-info.com", "Let's Encrypt", False),
    ("dz-passport-service.net", "Buypass", False),
    ("*.algeria-gov-portal.net", "Let's Encrypt", True),
    # Low risk / noise — should have low or zero score
    ("random-example.com", "DigiCert", False),
    ("github.com", "DigiCert", False),
    ("cloudflare.com", "Google Trust Services", False),
]


def _make_event(
    raw_domain: str,
    issuer: str,
    wildcard: bool,
    offset_minutes: int = 0,
) -> CertEvent:
    """Build a synthetic CertEvent for demo purposes."""
    domain = normalize_domain(raw_domain)
    parts = extract_parts(domain)
    tld = get_tld(domain)
    wildcard = wildcard or is_wildcard(raw_domain)

    result = score_domain(domain, issuer=issuer, is_wildcard=wildcard)

    now = datetime.now(tz=timezone.utc) - timedelta(minutes=offset_minutes)
    seen = now.isoformat()
    not_before = now.isoformat()
    not_after = (now + timedelta(days=90)).isoformat()

    fingerprint = f"demo-{uuid.uuid4().hex[:16]}"

    return CertEvent(
        domain=domain,
        raw_domain=raw_domain,
        registered_domain=parts["registered_domain"],
        tld=tld,
        issuer=issuer,
        seen_utc=seen,
        not_before_utc=not_before,
        not_after_utc=not_after,
        source="demo-feed",
        cert_link=f"https://crt.sh/?q={domain}",
        fingerprint=fingerprint,
        is_wildcard=wildcard,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        matched_keywords=result.matched_keywords,
        matched_brands=result.matched_brands,
        matched_suspicious_words=result.matched_suspicious_words,
        reasons=result.reasons,
    )


def inject_demo_events(min_score: int = 0) -> int:
    """Insert all demo events into the database.

    Args:
        min_score: Only insert events whose score >= min_score.

    Returns:
        Number of events actually inserted.
    """
    inserted = 0
    for i, (raw_domain, issuer, wildcard) in enumerate(_DEMO_DOMAINS):
        event = _make_event(raw_domain, issuer, wildcard, offset_minutes=i * 3)
        if event.risk_score < min_score:
            continue
        if insert_event(event):
            inserted += 1
            print(
                f"  [DEMO] {event.risk_level.upper():8s} score={event.risk_score:3d}  {event.domain}"
            )
    return inserted
