#!/usr/bin/env bash
# DZ Domain Watch — Startup script for GitHub Codespaces
# Runs automatically via devcontainer postStartCommand.
# 1) Tests crt.sh connectivity
# 2) Starts the crt.sh collector in the background
# 3) Launches Streamlit (stays in foreground so Codespaces keeps the port open)

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${GREEN}[DZ-WATCH]${NC} $*"; }
warn() { echo -e "${YELLOW}[DZ-WATCH]${NC} $*"; }
err()  { echo -e "${RED}[DZ-WATCH]${NC} $*"; }

echo -e "\n${BOLD}============================================================${NC}"
echo -e "${BOLD}  DZ Domain Watch — Démarrage automatique                   ${NC}"
echo -e "${BOLD}============================================================${NC}\n"

# ── 1. Connectivity check ──────────────────────────────────────────────────
log "Test de connectivité vers crt.sh…"
if python - <<'PYEOF'
import urllib.request, sys
url = 'https://crt.sh/?q=sonatrach&output=json&limit=1'
req = urllib.request.Request(url, headers={
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Accept': 'application/json'
})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        data = r.read()
        import json
        parsed = json.loads(data)
        print(f"crt.sh OK — {len(parsed)} certificat(s) reçu(s) pour 'sonatrach'", flush=True)
        sys.exit(0)
except Exception as e:
    print(f"crt.sh inaccessible: {e}", flush=True)
    sys.exit(1)
PYEOF
then
    log "✅ crt.sh accessible — données CT RÉELLES activées"
    CRTSH_OK=1
else
    warn "⚠️  crt.sh non accessible depuis ce réseau — mode DÉMO activé à la place"
    CRTSH_OK=0
fi

echo ""

# ── 2. Init DB ─────────────────────────────────────────────────────────────
log "Initialisation de la base de données…"
python scripts/init_db.py

# ── 3. Start collector ─────────────────────────────────────────────────────
if [ "$CRTSH_OK" -eq 1 ]; then
    log "Démarrage du collecteur crt.sh (certificats réels CT)…"
    nohup python -m dz_domain_watch.collector --source crtsh --min-score 30 \
        >> /tmp/dz_collector.log 2>&1 &
    COLLECTOR_PID=$!
    echo $COLLECTOR_PID > /tmp/dz_collector.pid
    log "Collecteur démarré (PID $COLLECTOR_PID) — logs: tail -f /tmp/dz_collector.log"
else
    log "Injection des données démo (certificats fictifs pour l'interface)…"
    python scripts/run_demo_data.py
fi

# ── 3b. Inject geo demo data (always, so War Room works even without crt.sh) ──
log "Injection des données Geo Intelligence War Room…"
python scripts/run_geo_demo_data.py || warn "run_geo_demo_data.py a échoué (non bloquant)"

# ── 3c. Start the continuous live-checker (online/offline status) ───────────
log "Démarrage du vérificateur 'Domaines Actifs' en arrière-plan…"
nohup python -m dz_domain_watch.live_checker --min-score 0 \
    >> /tmp/dz_live_checker.log 2>&1 &
LIVE_PID=$!
echo $LIVE_PID > /tmp/dz_live_checker.pid
log "Vérificateur live démarré (PID $LIVE_PID) — logs: tail -f /tmp/dz_live_checker.log"

echo ""

# ── 4. Launch Streamlit ────────────────────────────────────────────────────
log "Lancement du dashboard Streamlit sur le port 8501…"
echo -e "${BOLD}>>> Ouvre le port 8501 dans l'onglet 'Ports' de Codespaces <<<${NC}\n"

exec streamlit run app.py \
    --server.headless true \
    --server.address 0.0.0.0 \
    --server.port 8501 \
    --browser.gatherUsageStats false
