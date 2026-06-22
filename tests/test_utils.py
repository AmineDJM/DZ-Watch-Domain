"""Tests for dz_domain_watch.utils."""

import pytest
from dz_domain_watch.utils import (
    clean_text_for_matching,
    contains_keyword,
    count_hyphens,
    extract_parts,
    get_tld,
    is_wildcard,
    normalize_domain,
    parse_timestamp,
)


def test_normalize_domain_strips_wildcard():
    assert normalize_domain("*.airalgerie.dz") == "airalgerie.dz"


def test_normalize_domain_lowercase():
    assert normalize_domain("AirAlgerie.DZ") == "airalgerie.dz"


def test_normalize_domain_strips_whitespace():
    assert normalize_domain("  example.com  ") == "example.com"


def test_is_wildcard_true():
    assert is_wildcard("*.example.com") is True


def test_is_wildcard_false():
    assert is_wildcard("example.com") is False


def test_extract_parts_registered_domain():
    parts = extract_parts("sub.airalgerie.dz")
    assert parts["registered_domain"] == "airalgerie.dz"
    assert parts["subdomain"] == "sub"
    assert parts["suffix"] == "dz"


def test_extract_parts_no_subdomain():
    parts = extract_parts("baridimob.com")
    assert parts["domain"] == "baridimob"
    assert parts["subdomain"] == ""


def test_clean_text_removes_accents():
    assert clean_text_for_matching("algérie") == "algerie"


def test_contains_keyword_found():
    hits = contains_keyword("airalgerie-refund.com", ["airalgerie", "sonatrach"])
    assert "airalgerie" in hits


def test_contains_keyword_not_found():
    hits = contains_keyword("random-example.com", ["airalgerie", "sonatrach"])
    assert hits == []


def test_count_hyphens():
    assert count_hyphens("air-algerie-refund.com") >= 2


def test_get_tld_dot_com():
    assert get_tld("example.com") == ".com"


def test_get_tld_dot_xyz():
    assert get_tld("phishing.xyz") == ".xyz"


def test_parse_timestamp_unix():
    result = parse_timestamp(1700000000)
    assert "2023" in result


def test_parse_timestamp_none():
    assert parse_timestamp(None) is None
