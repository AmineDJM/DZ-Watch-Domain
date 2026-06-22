"""Risk scoring engine for DZ Domain Watch.

Scores range from 0 to 100. A high score signals a domain worth investigating —
it does NOT prove malicious intent. Always verify manually.
"""

import json
import os
from pathlib import Path
from typing import Optional

from rapidfuzz import fuzz

from .models import ScoreResult
from .utils import (
    clean_text_for_matching,
    contains_keyword,
    count_hyphens,
    extract_parts,
    get_tld,
    normalize_domain,
)

_WATCHLIST_PATH = Path(__file__).parent.parent / "config" / "watchlists.json"
_watchlist: Optional[dict] = None


# Allow env override for the watchlist path
def _get_watchlist_path() -> Path:
    env_path = os.environ.get("DZ_WATCHLIST_PATH")
    if env_path:
        return Path(env_path)
    return _WATCHLIST_PATH


def _load_watchlist_fresh() -> dict:
    path = _get_watchlist_path()
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def get_watchlist() -> dict:
    """Return the cached watchlist, loading it on first call."""
    global _watchlist
    if _watchlist is None:
        _watchlist = _load_watchlist_fresh()
    return _watchlist


def _fuzzy_brand_match(domain_clean: str, brands: list[str], threshold: int = 85) -> list[str]:
    """Return brands that fuzzy-match strongly against any segment of the domain."""
    matched = []
    parts = domain_clean.replace(".", "-").split("-")
    for brand in brands:
        brand_clean = clean_text_for_matching(brand).replace("-", "")
        # Check against full domain and individual segments
        candidates = [domain_clean.replace(".", "").replace("-", "")] + parts
        for candidate in candidates:
            if len(candidate) < 3:
                continue
            ratio = fuzz.ratio(brand_clean, candidate)
            if ratio >= threshold and brand not in matched:
                matched.append(brand)
    return matched


def score_domain(
    domain: str,
    issuer: str = "",
    is_wildcard: bool = False,
) -> ScoreResult:
    """Compute a risk score for a domain.

    Args:
        domain: The fully-qualified domain name (already normalized/lowercased).
        issuer: Certificate issuer string.
        is_wildcard: Whether the certificate is a wildcard.

    Returns:
        ScoreResult with score, level, matched lists, and human-readable reasons.
    """
    wl = get_watchlist()
    country_keywords: list[str] = wl.get("country_keywords", [])
    brands: list[str] = wl.get("brands", [])
    suspicious_words: list[str] = wl.get("suspicious_words", [])
    suspicious_tlds: list[str] = wl.get("suspicious_tlds", [])
    free_issuers: list[str] = wl.get("free_issuers", [])

    score = 0
    reasons: list[str] = []
    matched_keywords: list[str] = []
    matched_brands: list[str] = []
    matched_suspicious_words: list[str] = []

    domain_clean = clean_text_for_matching(domain)
    issuer_clean = clean_text_for_matching(issuer)
    tld = get_tld(domain)
    parts = extract_parts(domain)

    # --- Country keyword match (+15 base, not +40) ---
    # "dz" alone in a .dz domain is not suspicious by itself.
    kw_hits = contains_keyword(domain, country_keywords)
    if kw_hits:
        # Only count if "dz" appears somewhere OTHER than just the TLD
        non_tld_hits = [k for k in kw_hits if not (k == "dz" and tld == ".dz")]
        if non_tld_hits:
            matched_keywords = non_tld_hits
            score += 15
            reasons.append(f"Mot-clé pays détecté: {', '.join(non_tld_hits)}")
        elif kw_hits:
            # "dz" only in TLD — note it but don't inflate score
            matched_keywords = kw_hits

    # --- Brand match (exact substring, +30) ---
    brand_hits = contains_keyword(domain, brands)
    if brand_hits:
        matched_brands = brand_hits
        score += 30
        reasons.append(f"Marque algérienne détectée: {', '.join(brand_hits)}")

    # --- Fuzzy brand match (+15 if no exact match already) ---
    if not brand_hits:
        fuzzy_hits = _fuzzy_brand_match(domain_clean, brands, threshold=85)
        if fuzzy_hits:
            matched_brands = fuzzy_hits
            score += 15
            reasons.append(f"Similarité forte avec marque algérienne: {', '.join(fuzzy_hits)}")

    # --- Suspicious word match (+35) ---
    # This is the key escalator: a brand alone is informational, but
    # brand + suspicious word = genuinely concerning.
    sw_hits = contains_keyword(domain, suspicious_words)
    if sw_hits:
        matched_suspicious_words = sw_hits
        score += 35
        reasons.append(f"Mot suspect détecté: {', '.join(sw_hits)}")

    # --- Brand + suspicious word combo (+15 bonus) ---
    if matched_brands and matched_suspicious_words:
        score += 15
        reasons.append(
            f"Combinaison marque+mot-suspect: {matched_brands[0]} + {matched_suspicious_words[0]}"
        )

    # --- Suspicious TLD (+20) ---
    # A risky TLD (.xyz, .top, .ru…) is a strong signal on its own.
    if tld in suspicious_tlds:
        score += 20
        reasons.append(f"TLD à risque: {tld}")

    # --- Wildcard certificate (+10) ---
    if is_wildcard:
        score += 10
        reasons.append("Certificat wildcard")

    # --- Multiple hyphens (+5) ---
    hyphen_count = count_hyphens(domain)
    if hyphen_count >= 2:
        score += 5
        reasons.append(f"Nombreux tirets dans le domaine ({hyphen_count})")

    # --- Free issuer (+5) ---
    if any(fi in issuer_clean for fi in free_issuers):
        score += 5
        reasons.append(f"Issuer gratuit: {issuer}")

    # Clamp to [0, 100]
    score = min(100, max(0, score))

    # Determine level
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return ScoreResult(
        risk_score=score,
        risk_level=level,
        matched_keywords=matched_keywords,
        matched_brands=matched_brands,
        matched_suspicious_words=matched_suspicious_words,
        reasons=reasons,
    )
