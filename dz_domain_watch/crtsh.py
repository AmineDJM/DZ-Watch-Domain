"""crt.sh collector for DZ Domain Watch.

Alternative — and far more reliable — data source than the public CertStream
firehose. Instead of streaming every certificate in the world, it queries the
official Certificate Transparency search engine crt.sh (operated by Sectigo)
for a curated set of Algeria-related seed keywords, then scores every returned
domain with the full local watchlist.

This pulls REAL certificates from the public CT logs and works over plain
HTTPS, which makes it ideal for restricted networks and GitHub Codespaces.

Usage (wired through collector.py):
    python -m dz_domain_watch.collector --source crtsh
    python -m dz_domain_watch.collector --source crtsh --min-score 40 --once
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .db import init_db, insert_event
from .models import CertEvent
from .scoring import get_watchlist, score_domain
from .utils import extract_parts, get_tld, is_wildcard, normalize_domain

_CRTSH_URL = "https://crt.sh/?q={query}&output=json"
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)

# Colour helpers (mirror collector.py)
_RED, _YLW, _CYN, _GRN, _RST, _BLD = (
    "\033[91m", "\033[93m", "\033[96m", "\033[92m", "\033[0m", "\033[1m"
)
_LEVEL_COLOURS = {
    "critical": _RED + _BLD,
    "high": _RED,
    "medium": _YLW,
    "low": _GRN,
}


def _log(msg: str, level: str = "info") -> None:
    ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
    colour = {"info": _CYN, "warn": _YLW, "error": _RED, "ok": _GRN}.get(level, "")
    print(f"{colour}[{ts}] {msg}{_RST}", flush=True)


def _print_alert(event: CertEvent) -> None:
    colour = _LEVEL_COLOURS.get(event.risk_level, "")
    print(
        f"\n{colour}{'='*60}{_RST}\n"
        f"{colour}[ALERTE {event.risk_level.upper()}]{_RST} score={event.risk_score}\n"
        f"  Domaine  : {event.domain}\n"
        f"  Issuer   : {event.issuer}\n"
        f"  TLD      : {event.tld}\n"
        f"  Raisons  : {'; '.join(event.reasons)}\n"
        f"  Lien CT  : {event.cert_link or 'n/a'}\n"
        f"{colour}{'='*60}{_RST}",
        flush=True,
    )


def fetch_crtsh(query: str, timeout: int = 40, retries: int = 4) -> list[dict]:
    """Query crt.sh for a keyword and return the parsed JSON list.

    Retries on transient server errors (429/502/503/504) with exponential
    backoff, since the public crt.sh service is frequently overloaded.
    Returns an empty list on any unrecoverable error so the collector never
    crashes on a single failed lookup.
    """
    # Transient HTTP codes worth retrying (rate limit + gateway/overload errors)
    transient = {429, 500, 502, 503, 504}
    url = _CRTSH_URL.format(query=urllib.parse.quote(query))
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            if not raw:
                return []
            return json.loads(raw)
        except urllib.error.HTTPError as exc:
            if exc.code in transient and attempt < retries:
                wait = min(30, 3 * (2 ** attempt))  # 3,6,12,24,30s
                _log(f"crt.sh {exc.code} sur '{query}' — nouvel essai dans {wait}s…", "warn")
                time.sleep(wait)
                continue
            _log(f"crt.sh HTTP {exc.code} pour '{query}' (abandon)", "warn")
            return []
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt < retries:
                wait = min(30, 3 * (2 ** attempt))
                time.sleep(wait)
                continue
            _log(f"crt.sh erreur '{query}': {exc} (abandon)", "warn")
            return []
    return []


def _record_to_events(record: dict, min_score: int) -> list[CertEvent]:
    """Turn one crt.sh JSON record into scored CertEvent objects (one per SAN)."""
    events: list[CertEvent] = []

    cert_id = record.get("id")
    issuer = record.get("issuer_name") or "Unknown"
    not_before = record.get("not_before")
    not_after = record.get("not_after")
    entry_ts = record.get("entry_timestamp")
    seen_utc = entry_ts or datetime.now(tz=timezone.utc).isoformat()

    # name_value holds one or more domains separated by newlines (the SANs)
    raw_names = (record.get("name_value") or record.get("common_name") or "").split("\n")

    for raw_domain in raw_names:
        raw_domain = raw_domain.strip()
        if not raw_domain or " " in raw_domain:
            continue

        domain = normalize_domain(raw_domain)
        wildcard = is_wildcard(raw_domain)
        parts = extract_parts(domain)
        tld = get_tld(domain)

        result = score_domain(domain, issuer=issuer, is_wildcard=wildcard)
        if result.risk_score < min_score:
            continue

        events.append(
            CertEvent(
                domain=domain,
                raw_domain=raw_domain,
                registered_domain=parts["registered_domain"],
                tld=tld,
                issuer=issuer,
                seen_utc=seen_utc,
                not_before_utc=not_before,
                not_after_utc=not_after,
                source="crt.sh",
                cert_link=f"https://crt.sh/?id={cert_id}" if cert_id else None,
                fingerprint=f"crtsh-{cert_id}" if cert_id else f"crtsh-{domain}-{seen_utc}",
                is_wildcard=wildcard,
                risk_score=result.risk_score,
                risk_level=result.risk_level,
                matched_keywords=result.matched_keywords,
                matched_brands=result.matched_brands,
                matched_suspicious_words=result.matched_suspicious_words,
                reasons=result.reasons,
            )
        )
    return events


def run_one_pass(min_score: int, polite_delay: float = 3.0) -> int:
    """Run a single sweep over all crt.sh seed keywords. Returns new alerts count."""
    wl = get_watchlist()
    seeds = wl.get("crtsh_seeds") or wl.get("country_keywords", [])
    new_alerts = 0
    total_certs = 0

    _log(f"Début d'une passe sur {len(seeds)} mots-clés algériens…", "info")

    for i, seed in enumerate(seeds, 1):
        records = fetch_crtsh(seed)
        total_certs += len(records)
        if records:
            _log(f"[{i:2d}/{len(seeds)}] '{seed}': {len(records)} certificats CT", "info")
        for record in records:
            for event in _record_to_events(record, min_score):
                if insert_event(event):
                    new_alerts += 1
                    _print_alert(event)
        time.sleep(polite_delay)  # poli avec le service public crt.sh

    _log(f"Passe terminée — {total_certs} certificats analysés, {new_alerts} nouvelle(s) alerte(s).", "ok")
    return new_alerts


def run_crtsh_collector(
    min_score: int = 30,
    poll_interval: int = 600,
    once: bool = False,
) -> None:
    """Run the crt.sh collector, optionally looping forever.

    Args:
        min_score: minimum risk score to store an event.
        poll_interval: seconds to wait between full sweeps (default 10 min).
        once: if True, run a single sweep and exit (useful for testing/cron).
    """
    init_db()
    _log("=" * 60, "ok")
    _log("DZ Domain Watch — Collecteur CT (source: crt.sh)", "ok")
    _log(f"Score minimum : {min_score}", "ok")
    _log(f"Intervalle    : {poll_interval}s entre chaque passe", "ok")
    _log("Source RÉELLE : Certificate Transparency logs via crt.sh", "ok")
    _log("=" * 60, "ok")

    sweep = 0
    while True:
        sweep += 1
        _log(f"═══ Passe #{sweep} ═══", "info")
        try:
            run_one_pass(min_score)
        except KeyboardInterrupt:
            _log("Arrêt du collecteur crt.sh.", "warn")
            return
        except Exception as exc:
            _log(f"Erreur durant la passe #{sweep}: {exc}", "error")

        if once:
            _log("Mode --once : arrêt après une passe.", "warn")
            return

        _log(f"Prochaine passe dans {poll_interval}s — Ctrl+C pour arrêter.", "info")
        try:
            time.sleep(poll_interval)
        except KeyboardInterrupt:
            _log("Arrêt du collecteur crt.sh.", "warn")
            return
