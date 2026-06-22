"""Initialize the DZ Domain Watch SQLite database."""

import sys
from pathlib import Path

# Allow running from project root without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent))

from dz_domain_watch.db import init_db

if __name__ == "__main__":
    init_db()
    print("Base de données initialisée avec succès.")
