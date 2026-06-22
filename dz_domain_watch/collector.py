"""CertStream collector for DZ Domain Watch.

Connects to the public CertStream WebSocket feed, filters Algeria-related
certificate events, scores them, and persists them to SQLite.

Usage:
    python -m dz_domain_watch.collector
    python -m dz_domain_watch.collector --min-score 40
    python -m dz_domain_watch.collector --debug
    python -m dz_domain_watch.collector --demo
"""

import argparse
import sys
import time
from datetime import datetime, timezone

import certstream

from .db import init_db, insert_event
from .models import CertEvent
from .scoring import score_domain
from .utils import (
    extract_parts,
    get_tld,
    is_wildcard,
    normalize_domain,
    parse_timestamp,
    safe_get,
)

# ANSI colour helpers
_RED = "\033[91m"
_YLW = "\033[93m"
_CYN = "\033[96m"
_GRN = "\033[92m"
_RST = "\033[0m"
_BLD = "\033[1m"

LEVEL_COLOURS = {
    "critical": _RED + _BLD,
    "high": _RED,
    "medium": _YLW,
    "low": _GRN,
}

MIN_SCORE_DEFAULT = 30
_debug_mode = False
_min_score = MIN_SCORE_DEFAULT


def _log(msg: str, level: str = "info") -> None:
    ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
    colour = {"info": _CYN, "warn": _YLW, "error": _RED, "ok": _GRN}.get(level, "")
    print(f"{colour}[{ts}] {msg}{_RST}", flush=True)


def _print_alert(event: CertEvent) -> None:
    colour = LEVEL_COLOURS.get(event.risk_level, "")
    print(
        f"\n{colour}{'='*60}{_RST}\n"
        f"{colour}[ALERTE {event.risk_level.upper()}]{_RST} score={event.risk_score}\n"
        f"  Domaine  : {event.domain}\n"
        f"  Issuer   : {event.issuer}\n"
        f"  TLD      : {event.tld}\n"
        f"  Wildcard : {'oui' if event.is_wildcard else 'non'}\n"
        f"  Raisons  : {'; '.join(event.reasons)}\n"
        f"  Lien CT  : {event.cert_link or 'n/a'}\n"
        f"{colour}{'='*60}{_RST}",
        flush=True,
    )


def _parse_message(message: dict) -> list[CertEvent]:
    """Extract CertEvent objects from a CertStream message dict."""
    events: list[CertEvent] = []

    msg_type = safe_get(message, "message_type")
    if msg_type != "certificate_update":
        return events

    data = safe_get(message, "data", default={})
    leaf = safe_get(data, "leaf_cert", default={})

    all_domains: list[str] = safe_get(leaf, "all_domains") or []
    if not all_domains:
        return events

    issuer_data = safe_get(leaf, "issuer") or {}
    issuer_org = safe_get(issuer_data, "O") or safe_get(issuer_data, "CN") or "Unknown"

    seen_ts = safe_get(data, "seen") or safe_get(data, "cert_index")
    seen_utc = parse_timestamp(seen_ts) or datetime.now(tz=timezone.utc).isoformat()

    validity = safe_get(leaf, "validity") or {}
    not_before_utc = parse_timestamp(safe_get(validity, "start"))
    not_after_utc = parse_timestamp(safe_get(validity, "end"))

    source_name = safe_get(data, "source", "name") or "unknown"
    cert_link = safe_get(data, "cert_link")
    fingerprint = safe_get(leaf, "fingerprint")

    for raw_domain in all_domains:
        if not raw_domain:
            continue

        domain = normalize_domain(raw_domain)
        wildcard = is_wildcard(raw_domain)
        parts = extract_parts(domain)
        tld = get_tld(domain)

        result = score_domain(domain, issuer=issuer_org, is_wildcard=wildcard)

        if result.risk_score < _min_score:
            if _debug_mode:
                _log(f"skip (score={result.risk_score}) {domain}", "info")
            continue

        event = CertEvent(
            domain=domain,
            raw_domain=raw_domain,
            registered_domain=parts["registered_domain"],
            tld=tld,
            issuer=issuer_org,
            seen_utc=seen_utc,
            not_before_utc=not_before_utc,
            not_after_utc=not_after_utc,
            source=source_name,
            cert_link=cert_link,
            fingerprint=fingerprint or f"nofp-{domain}-{seen_utc}",
            is_wildcard=wildcard,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            matched_keywords=result.matched_keywords,
            matched_brands=result.matched_brands,
            matched_suspicious_words=result.matched_suspicious_words,
            reasons=result.reasons,
        )
        events.append(event)

    return events


def _on_message(message: dict, context) -> None:
    """CertStream callback: parse and store matching events."""
    try:
        events = _parse_message(message)
        for event in events:
            inserted = insert_event(event)
            if inserted:
                _print_alert(event)
            elif _debug_mode:
                _log(f"duplicate skipped: {event.domain}", "info")
    except Exception as exc:
        _log(f"Erreur lors du traitement du message: {exc}", "error")


def _on_error(instance, exception) -> None:
    _log(f"CertStream erreur: {exception} — reconnexion en cours…", "warn")


def run_collector(min_score: int = MIN_SCORE_DEFAULT, debug: bool = False) -> None:
    """Start the CertStream listener (blocks until interrupted)."""
    global _min_score, _debug_mode
    _min_score = min_score
    _debug_mode = debug

    init_db()
    _log(f"DZ Domain Watch — Collector démarré (score minimum: {min_score})", "ok")
    _log("En attente de certificats CertStream… (Ctrl+C pour arrêter)", "info")

    while True:
        try:
            certstream.listen_for_events(
                _on_message,
                on_error=_on_error,
                url="wss://certstream.calidog.io/",
            )
        except KeyboardInterrupt:
            _log("Arrêt du collector.", "warn")
            sys.exit(0)
        except Exception as exc:
            _log(f"Connexion perdue: {exc} — nouvelle tentative dans 10s…", "warn")
            time.sleep(10)


def run_demo(min_score: int = 0) -> None:
    """Inject synthetic demo events into the database for UI testing."""
    from .demo import inject_demo_events

    init_db()
    _log("Mode DEMO — injection d'événements fictifs…", "ok")
    count = inject_demo_events(min_score=min_score)
    _log(f"{count} événements demo insérés.", "ok")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DZ Domain Watch — Collector CertStream"
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=MIN_SCORE_DEFAULT,
        help="Score minimum pour enregistrer un événement (défaut: 30)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Afficher les domaines filtrés (score trop bas)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Injecter des données fictives pour tester l'interface",
    )
    args = parser.parse_args()

    if args.demo:
        run_demo(min_score=args.min_score)
    else:
        run_collector(min_score=args.min_score, debug=args.debug)


if __name__ == "__main__":
    main()
