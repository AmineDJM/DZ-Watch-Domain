"""Inject demo data into the DZ Domain Watch database for UI testing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dz_domain_watch.db import init_db
from dz_domain_watch.demo import inject_demo_events

if __name__ == "__main__":
    print("DZ Domain Watch — Injection de données démo")
    print("=" * 50)
    init_db()
    count = inject_demo_events(min_score=0)
    print("=" * 50)
    print(f"Terminé : {count} événement(s) inséré(s).")
    print("Lancez maintenant : streamlit run app.py")
