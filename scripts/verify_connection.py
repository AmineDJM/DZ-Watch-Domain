"""
Test de connectivité vers les sources CT publiques.
Lance ce script pour vérifier que ton environnement peut récupérer
de vrais certificats Certificate Transparency.

Usage: python scripts/verify_connection.py
"""

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

GREEN = "\033[92m"
RED = "\033[91m"
YLW = "\033[93m"
BLD = "\033[1m"
RST = "\033[0m"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
    ),
    "Accept": "application/json",
}

SEEDS = ["sonatrach", "algerie", "mobilis", "djezzy", "airalgerie"]


def fetch_test(seed: str, limit: int = 5) -> list[dict]:
    url = f"https://crt.sh/?q={seed}&output=json&limit={limit}"
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read())


def main() -> None:
    print(f"\n{BLD}{'='*60}{RST}")
    print(f"{BLD}DZ Domain Watch — Vérification connexion CT (crt.sh){RST}")
    print(f"{BLD}{'='*60}{RST}\n")
    print(f"Heure : {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

    ok_count = 0
    for seed in SEEDS:
        try:
            records = fetch_test(seed, limit=3)
            print(
                f"{GREEN}✅ '{seed}'{RST} — {len(records)} certificat(s) réel(s) reçu(s)"
            )
            for r in records[:2]:
                name = (r.get("common_name") or r.get("name_value") or "?").split("\n")[0]
                issuer = (r.get("issuer_name") or "?")[:50]
                nb = (r.get("not_before") or "?")[:10]
                print(f"    → {name}  |  issuer: {issuer}  |  date: {nb}")
            ok_count += 1
        except urllib.error.HTTPError as exc:
            print(f"{RED}❌ '{seed}'{RST} — HTTP {exc.code} ({exc.reason})")
        except Exception as exc:
            print(f"{RED}❌ '{seed}'{RST} — {type(exc).__name__}: {exc}")

    print(f"\n{BLD}{'='*60}{RST}")
    if ok_count == len(SEEDS):
        print(f"{GREEN}{BLD}✅ CONNEXION OK — données CT réelles disponibles{RST}")
        print(f"   Le collecteur récupérera de vrais certificats algériens.")
        sys.exit(0)
    elif ok_count > 0:
        print(f"{YLW}{BLD}⚠️  CONNEXION PARTIELLE ({ok_count}/{len(SEEDS)} seeds OK){RST}")
        sys.exit(0)
    else:
        print(f"{RED}{BLD}❌ CONNEXION ÉCHOUÉE — crt.sh inaccessible depuis ce réseau{RST}")
        print(f"   Mode démo (données fictives) sera utilisé à la place.")
        sys.exit(1)


if __name__ == "__main__":
    main()
