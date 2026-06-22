#!/usr/bin/env bash
# Affiche les logs du collecteur en temps réel.
# Usage : bash scripts/check_logs.sh
LOG=/tmp/dz_collector.log
if [ -f "$LOG" ]; then
    echo "=== Logs du collecteur DZ Domain Watch ==="
    tail -f "$LOG"
else
    echo "Aucun log trouvé. Le collecteur n'a peut-être pas encore démarré."
    echo "Relance le Codespace ou exécute : bash scripts/start.sh"
fi
