"""Tests for dz_domain_watch.scoring."""

import pytest
from dz_domain_watch.scoring import score_domain


def test_airalgerie_refund_is_critical():
    result = score_domain("airalgerie-refund.com", issuer="Let's Encrypt", is_wildcard=False)
    assert result.risk_score >= 80
    assert result.risk_level == "critical"
    assert len(result.matched_brands) > 0
    assert len(result.matched_suspicious_words) > 0


def test_random_domain_is_low():
    result = score_domain("random-example.com", issuer="DigiCert", is_wildcard=False)
    assert result.risk_score < 40
    assert result.risk_level == "low"
    assert result.matched_brands == []
    assert result.matched_keywords == []


def test_country_keyword_gives_score():
    result = score_domain("algerie-visa.com", issuer="ZeroSSL", is_wildcard=False)
    assert result.risk_score >= 40
    assert "algerie" in result.matched_keywords or any(
        "algerie" in kw for kw in result.matched_keywords
    )


def test_suspicious_tld_adds_score():
    base = score_domain("sonatrach.com", issuer="Let's Encrypt", is_wildcard=False)
    xyz = score_domain("sonatrach.xyz", issuer="Let's Encrypt", is_wildcard=False)
    assert xyz.risk_score >= base.risk_score


def test_wildcard_adds_score():
    normal = score_domain("mobilis.com", issuer="Let's Encrypt", is_wildcard=False)
    wild = score_domain("mobilis.com", issuer="Let's Encrypt", is_wildcard=True)
    assert wild.risk_score > normal.risk_score


def test_score_capped_at_100():
    result = score_domain(
        "airalgerie-login-verify-secure.xyz",
        issuer="Let's Encrypt",
        is_wildcard=True,
    )
    assert result.risk_score <= 100


def test_reasons_not_empty_for_high_risk():
    result = score_domain("baridimob-verification.net", issuer="ZeroSSL", is_wildcard=False)
    assert len(result.reasons) > 0


def test_score_result_structure():
    result = score_domain("djezzy-account.com", issuer="Buypass", is_wildcard=False)
    assert hasattr(result, "risk_score")
    assert hasattr(result, "risk_level")
    assert hasattr(result, "matched_keywords")
    assert hasattr(result, "matched_brands")
    assert hasattr(result, "matched_suspicious_words")
    assert hasattr(result, "reasons")
    assert result.risk_level in ("low", "medium", "high", "critical")
