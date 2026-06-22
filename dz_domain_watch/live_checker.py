"""Continuous background live-checker for DZ Domain Watch.

Runs in a loop: pulls candidate domains from cert_events, checks which are
actually online (HTTP HEAD), and writes the verdict to the live_status table.
The Streamlit dashboard simply reads that table — so verification keeps
running in real time even across UI auto-refreshes.

Can run two ways:
  - As a standalone process : python -m dz_domain_watch.live_checker
  - Auto-started inside Streamlit via ensure_started() (one daemon thread).
"""

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .db import fetch_events, init_db
from .live_check import check_domain_live
from .live_db import init_live_db, upsert_live_status, fetch_live_status_map

# How long before a domain is re-checked (seconds)
_RECHECK_AFTER = 300
# Domains checked per batch / concurrency
_BATCH_SIZE = 20
_MAX_WORKERS = 15
# Pause between batches so we don't hammer
_BATCH_PAUSE = 1.0
# Pause when there's nothing new to check
_IDLE_PAUSE = 10.0

_started = False
_start_lock = threading.Lock()


def _is_stale(checked_at: Optional[str]) -> bool:
    if not checked_at:
        return True
    try:
        dt = datetime.fromisoformat(checked_at)
        age = (datetime.now(tz=timezone.utc) - dt).total_seconds()
        return age >= _RECHECK_AFTER
    except Exception:
        return True


def _select_candidates(min_score: int, limit: int) -> list[str]:
    """Domains worth checking: score >= min, not checked recently."""
    events = fetch_events(min_score=min_score, limit=2000)
    status_map = fetch_live_status_map()

    # Unique domains, preserve highest-score-first order from fetch_events
    seen = set()
    candidates: list[str] = []
    for ev in events:
        dom = ev.get("domain")
        if not dom or dom in seen:
            continue
        seen.add(dom)
        existing = status_map.get(dom)
        if existing is None or _is_stale(existing.get("checked_at")):
            candidates.append(dom)
        if len(candidates) >= limit:
            break
    return candidates


def check_batch(domains: list[str]) -> int:
    """Check a batch of domains concurrently and store results. Returns count."""
    import concurrent.futures

    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(check_domain_live, d): d for d in domains}
        for fut in concurrent.futures.as_completed(futures):
            dom = futures[fut]
            try:
                result = fut.result()
            except Exception as exc:
                result = {
                    "domain": dom,
                    "is_live": False,
                    "status_code": None,
                    "server": None,
                    "redirect_url": None,
                    "checked_at": datetime.now(tz=timezone.utc).isoformat(),
                    "error": str(exc),
                }
            upsert_live_status(result)
            count += 1
    return count


def run_live_loop(min_score: int = 0, stop_event: Optional[threading.Event] = None) -> None:
    """Continuously verify domains. Designed to run forever in the background."""
    init_db()
    init_live_db()
    print(f"[LIVE] Vérificateur live démarré (min_score={min_score})", flush=True)

    while True:
        if stop_event is not None and stop_event.is_set():
            return
        try:
            candidates = _select_candidates(min_score, _BATCH_SIZE)
            if not candidates:
                time.sleep(_IDLE_PAUSE)
                continue
            n = check_batch(candidates)
            print(
                f"[LIVE] {datetime.now(tz=timezone.utc).strftime('%H:%M:%S')} "
                f"— {n} domaine(s) vérifié(s)",
                flush=True,
            )
            time.sleep(_BATCH_PAUSE)
        except Exception as exc:
            print(f"[LIVE] erreur boucle : {exc}", flush=True)
            time.sleep(_IDLE_PAUSE)


def ensure_started(min_score: int = 0) -> bool:
    """Start the background checker exactly once per process. Safe to call repeatedly.

    Returns True if it started it now, False if already running.
    """
    global _started
    with _start_lock:
        if _started:
            return False
        _started = True

    init_live_db()
    thread = threading.Thread(
        target=run_live_loop,
        kwargs={"min_score": min_score},
        daemon=True,
        name="dz-live-checker",
    )
    thread.start()
    return True


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="DZ Domain Watch — vérificateur live")
    parser.add_argument("--min-score", type=int, default=0)
    args = parser.parse_args()
    run_live_loop(min_score=args.min_score)


if __name__ == "__main__":
    _main()
