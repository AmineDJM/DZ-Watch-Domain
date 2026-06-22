"""Live domain reachability checker for DZ Domain Watch.

Does a lightweight HTTP HEAD request to check if a domain is actually online.
Uses a short timeout to avoid blocking the UI.
Results are cached in SQLite so we don't re-check the same domain repeatedly.
"""

import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

_TIMEOUT = 6
_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"


def check_domain_live(domain: str) -> dict:
    """
    Check if a domain is reachable via HTTP/HTTPS.
    Returns a dict with: is_live, status_code, redirect_url, checked_at, error.
    """
    result = {
        "domain": domain,
        "is_live": False,
        "status_code": None,
        "redirect_url": None,
        "server": None,
        "checked_at": datetime.now(tz=timezone.utc).isoformat(),
        "error": None,
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            req = urllib.request.Request(
                url,
                method="HEAD",
                headers={
                    "User-Agent": _USER_AGENT,
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            # Don't follow redirects so we see the raw response
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )
            with opener.open(req, timeout=_TIMEOUT) as resp:
                result["is_live"] = True
                result["status_code"] = resp.status
                result["server"] = resp.headers.get("Server", "")
                result["redirect_url"] = resp.headers.get("Location", "")
            return result
        except urllib.error.HTTPError as exc:
            # 4xx/5xx still means the server is alive
            result["is_live"] = True
            result["status_code"] = exc.code
            return result
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            result["error"] = str(exc)
            # Try next scheme
            continue

    return result


def bulk_check(domains: list[str], max_workers: int = 10) -> dict[str, dict]:
    """Check multiple domains concurrently. Returns {domain: result}."""
    import concurrent.futures

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check_domain_live, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                results[domain] = future.result()
            except Exception as exc:
                results[domain] = {
                    "domain": domain,
                    "is_live": False,
                    "status_code": None,
                    "redirect_url": None,
                    "server": None,
                    "checked_at": datetime.now(tz=timezone.utc).isoformat(),
                    "error": str(exc),
                }
    return results
