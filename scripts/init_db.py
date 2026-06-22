"""Initialize the DZ Domain Watch SQLite database."""

import sys
from pathlib import Path

# Allow running from project root without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent))

from dz_domain_watch.db import init_db
from dz_domain_watch.geo_db import init_geo_db

if __name__ == "__main__":
    init_db()
    init_geo_db()
    print("Base de données initialisée avec succès (alertes CT + tables Geo).")
