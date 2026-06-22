"""Tests for dz_domain_watch.db (using a temporary in-memory-style DB file)."""

import tempfile
from pathlib import Path

import pytest
from dz_domain_watch.db import fetch_events, fetch_stats, init_db, insert_event
from dz_domain_watch.models import CertEvent


def _make_event(domain: str = "test.com", fingerprint: str = "fp-test-001") -> CertEvent:
    return CertEvent(
        domain=domain,
        raw_domain=domain,
        registered_domain=domain,
        tld=".com",
        issuer="Let's Encrypt",
        seen_utc="2024-01-01T12:00:00+00:00",
        not_before_utc="2024-01-01T00:00:00+00:00",
        not_after_utc="2024-04-01T00:00:00+00:00",
        source="test-feed",
        cert_link="https://crt.sh/?q=test",
        fingerprint=fingerprint,
        is_wildcard=False,
        risk_score=75,
        risk_level="high",
        matched_keywords=["dz"],
        matched_brands=["airalgerie"],
        matched_suspicious_words=["login"],
        reasons=["Test reason"],
    )


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "test.db"
    init_db(db_path)
    return db_path


def test_init_db_creates_file(tmp_db: Path):
    assert tmp_db.exists()


def test_insert_event_returns_true(tmp_db: Path):
    event = _make_event()
    assert insert_event(event, db_path=tmp_db) is True


def test_insert_duplicate_returns_false(tmp_db: Path):
    event = _make_event()
    insert_event(event, db_path=tmp_db)
    assert insert_event(event, db_path=tmp_db) is False


def test_fetch_events_returns_inserted(tmp_db: Path):
    event = _make_event(domain="airalgerie-refund.com", fingerprint="fp-unique-abc")
    insert_event(event, db_path=tmp_db)
    rows = fetch_events(db_path=tmp_db)
    assert any(r["domain"] == "airalgerie-refund.com" for r in rows)


def test_fetch_events_min_score_filter(tmp_db: Path):
    low = _make_event(domain="low.com", fingerprint="fp-low")
    low.risk_score = 10
    low.risk_level = "low"
    high = _make_event(domain="high.com", fingerprint="fp-high")
    high.risk_score = 80
    high.risk_level = "critical"
    insert_event(low, db_path=tmp_db)
    insert_event(high, db_path=tmp_db)

    rows = fetch_events(min_score=50, db_path=tmp_db)
    domains = [r["domain"] for r in rows]
    assert "high.com" in domains
    assert "low.com" not in domains


def test_fetch_stats_totals(tmp_db: Path):
    insert_event(_make_event(domain="a.com", fingerprint="fp-a"), db_path=tmp_db)
    insert_event(_make_event(domain="b.com", fingerprint="fp-b"), db_path=tmp_db)
    stats = fetch_stats(db_path=tmp_db)
    assert stats["total_events"] == 2
    assert stats["unique_domains"] == 2


def test_deduplication_same_domain_different_fingerprint(tmp_db: Path):
    e1 = _make_event(domain="dup.com", fingerprint="fp-dup-1")
    e2 = _make_event(domain="dup.com", fingerprint="fp-dup-2")
    r1 = insert_event(e1, db_path=tmp_db)
    r2 = insert_event(e2, db_path=tmp_db)
    assert r1 is True
    assert r2 is True  # Different fingerprint = new row
    rows = fetch_events(db_path=tmp_db)
    dup_rows = [r for r in rows if r["domain"] == "dup.com"]
    assert len(dup_rows) == 2
