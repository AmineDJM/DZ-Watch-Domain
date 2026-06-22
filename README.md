# 🛡️ DZ Domain Watch

> A OSINT dashboard that monitors live Certificate Transparency events and detects potentially suspicious domains related to Algeria.

---

## Qu'est-ce que DZ Domain Watch ?

**DZ Domain Watch** est un outil OSINT défensif qui surveille en temps réel les nouveaux certificats SSL/TLS publiés dans les **Certificate Transparency (CT) logs** via [CertStream](https://certstream.calidog.io/).

Il filtre les domaines potentiellement liés à l'Algérie, calcule un score de risque, stocke les événements en SQLite, et les affiche dans un dashboard web local.

### Ce qu'il fait

- Se connecte au flux public CertStream (WebSocket)
- Filtre les domaines contenant des mots-clés algériens ou ressemblant à des marques/institutions algériennes
- Calcule un score de risque de 0 à 100
- Stocke les alertes dans une base SQLite locale
- Affiche un dashboard Streamlit avec KPIs, filtres, tableau et graphiques
- Se reconnecte automatiquement si la connexion CertStream est perdue

### Ce qu'il ne fait pas

- Aucun accès non autorisé à des systèmes tiers
- Aucun scan actif (pas de requêtes HTTP vers les domaines détectés)
- Aucun test de mot de passe ou tentative d'intrusion
- Aucune dépendance à des API payantes (Shodan, Censys, etc.)
- Aucune intelligence sociale (réseaux sociaux, emails)

---

## Pourquoi les certificats SSL/TLS sont utiles pour l'OSINT défensif ?

Les Certificate Transparency logs sont des journaux publics imposés par les navigateurs depuis 2018. **Chaque certificat SSL émis doit y être inscrit** — y compris les certificats de domaines malveillants ou de phishing.

Cela signifie qu'en surveillant ces logs, on peut détecter des domaines suspects **avant même qu'ils soient utilisés** dans une attaque.

Exemples de ce qu'on peut détecter :
- `airalgerie-refund.com` → phishing Air Algérie
- `baridimob-verification.net` → faux site BaridiMob
- `aadl-inscription-2026.com` → usurpation AADL

### Différence entre nouveau domaine et nouveau certificat

| Aspect | Nouveau domaine | Nouveau certificat |
|---|---|---|
| Signification | Domaine enregistré pour la première fois | Certificat SSL émis pour ce domaine |
| Détectable via CT | Non (via WHOIS/zone files) | **Oui** |
| Délai | Quelques jours | Quelques secondes/minutes |
| Volume | Millions/jour | Millions/jour |

Un même domaine peut générer plusieurs certificats (renouvellement, sous-domaines). CertStream notifie à chaque émission.

---

## Installation

### Prérequis

- Python 3.11 ou supérieur
- pip
- Connexion internet (pour CertStream)

### Ubuntu / Linux

```bash
# Cloner ou copier le projet
cd dz-domain-watch

# Créer l'environnement virtuel
python3 -m venv .venv
source .venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Initialiser la base de données
python scripts/init_db.py
```

### Windows (PowerShell)

```powershell
# Dans le dossier du projet
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scripts/init_db.py
```

---

## Lancement

### Mode normal (CertStream live)

Ouvrir **deux terminaux** :

**Terminal 1 — Collector :**
```bash
source .venv/bin/activate
python -m dz_domain_watch.collector
```

**Terminal 2 — Dashboard :**
```bash
source .venv/bin/activate
streamlit run app.py
```

Puis ouvrir : [http://localhost:8501](http://localhost:8501)

### Options du collector

```bash
# Score minimum personnalisé (défaut: 30)
python -m dz_domain_watch.collector --min-score 40

# Mode debug (affiche les domaines filtrés)
python -m dz_domain_watch.collector --debug

# Mode démo (injecte des données fictives)
python -m dz_domain_watch.collector --demo
```

---

## Mode démo

Le mode démo injecte des événements fictifs dans la base de données pour permettre de tester l'interface **sans attendre de vrais matches CertStream**.

```bash
python scripts/run_demo_data.py
```

Ou via le collector :

```bash
python -m dz_domain_watch.collector --demo
```

Les domaines démo injectés incluent :
- `airalgerie-refund-support.com` → score critical
- `baridimob-verification.net` → score critical
- `aadl-inscription-2026.com` → score high
- `poste-dz-login.xyz` → score critical
- `sonatrach-careers.org` → score high
- `mobilis-secure-update.com` → score critical
- `random-example.com` → score low (filtré si min-score > 0)

---

## Tests

```bash
source .venv/bin/activate
pytest
```

Avec couverture :
```bash
pytest --cov=dz_domain_watch --cov-report=term-missing
```

---

## Architecture

```
CertStream (WebSocket public)
        │
        ▼
collector.py          ← écoute le flux, filtre, parse
        │
        ▼
scoring.py            ← calcule le score de risque (0-100)
        │
        ▼
db.py (SQLite WAL)    ← stocke les alertes, évite les doublons
        │
        ▼
app.py (Streamlit)    ← dashboard web local (port 8501)
```

---

## Structure des fichiers

```
dz-domain-watch/
├── README.md                      ← ce fichier
├── requirements.txt               ← dépendances Python
├── .env.example                   ← configuration optionnelle
├── app.py                         ← dashboard Streamlit
├── config/
│   └── watchlists.json            ← mots-clés, marques, TLDs surveillés
├── dz_domain_watch/
│   ├── __init__.py
│   ├── collector.py               ← listener CertStream
│   ├── db.py                      ← couche SQLite
│   ├── scoring.py                 ← moteur de scoring
│   ├── models.py                  ← dataclasses
│   ├── utils.py                   ← fonctions utilitaires
│   └── demo.py                    ← générateur de données fictives
├── scripts/
│   ├── init_db.py                 ← initialisation DB
│   └── run_demo_data.py           ← injection données démo
├── tests/
│   ├── test_scoring.py
│   ├── test_utils.py
│   └── test_db.py
└── data/
    ├── .gitkeep
    └── dz_watch.db                ← base SQLite (créée automatiquement)
```

---

## Comment modifier les watchlists ?

Éditez le fichier `config/watchlists.json` :

### Ajouter un mot-clé pays
```json
"country_keywords": [
  "algerie",
  "monnouvelmotcle"
]
```

### Ajouter une marque ou institution
```json
"brands": [
  "airalgerie",
  "nouvellemarque"
]
```

### Ajouter un mot suspect
```json
"suspicious_words": [
  "login",
  "nouveaumot"
]
```

### Ajouter un TLD à surveiller
```json
"suspicious_tlds": [
  ".top",
  ".nouveautld"
]
```

Les changements sont pris en compte au **prochain redémarrage du collector**.

---

## Logique de scoring

| Condition | Points |
|---|---|
| Mot-clé pays (algerie, dz…) | +40 |
| Marque algérienne (airalgerie, baridimob…) | +40 |
| Mot suspect (login, verify, refund…) | +25 |
| Similarité forte avec une marque (rapidfuzz ≥ 85%) | +15 |
| Combinaison marque + mot-suspect | +10 bonus |
| TLD à risque (.xyz, .top, .shop…) | +10 |
| Certificat wildcard | +10 |
| Nombreux tirets (≥ 2) | +5 |
| Issuer gratuit (Let's Encrypt, ZeroSSL…) | +5 |

**Niveaux :**
- 0–39 → 🟢 low
- 40–59 → 🟡 medium
- 60–79 → 🟠 high
- 80–100 → 🔴 critical

---

## Limites de l'outil

1. **Faux positifs** : un score élevé ne prouve pas qu'un domaine est malveillant. Vérifiez toujours manuellement.
2. **Couverture** : CertStream ne couvre pas 100% des certificats. Certains logs CT peuvent avoir un délai.
3. **Pas de WHOIS** : l'outil ne récupère pas les informations d'enregistrement des domaines.
4. **Pas de résolution DNS** : l'outil ne vérifie pas si le domaine résout ou pointe vers une IP.
5. **Volume** : le flux CertStream peut être très dense. Le filtrage par score permet de réduire le bruit.
6. **Langue** : la détection de mots arabes (الجزائر) fonctionne si le domaine est en Unicode, ce qui est rare pour les domaines enregistrés.

---

## Règles éthiques et légales

> Cet outil est conçu pour de l'OSINT défensif à partir de sources publiques.
> Il ne réalise pas d'accès non autorisé, ne contourne aucune protection,
> ne teste aucun mot de passe et ne scanne pas d'infrastructures tierces.
> Un score élevé indique un signal à vérifier, **pas une preuve de malveillance**.

- Utilisation réservée à des fins défensives, éducatives ou de recherche
- Ne pas utiliser pour cibler, harceler ou attaquer des tiers
- Respecter les lois locales sur la cybersécurité (Algérie : loi 18-07, France : RGPD / LPM)
- Signaler les domaines suspects aux organismes compétents (CERT-DZ, institutions concernées)

---

## Dépannage

### "ModuleNotFoundError: No module named 'certstream'"
```bash
pip install -r requirements.txt
```

### "database is locked"
Le mode WAL est activé par défaut. Si le problème persiste, vérifiez qu'il n'y a pas deux processus en écriture simultanée sur le même fichier.

### Le collector tourne mais aucune alerte n'apparaît
- Attendez quelques minutes (le flux CertStream est dense mais les matches algériens sont rares)
- Réduisez le score minimum : `python -m dz_domain_watch.collector --min-score 10`
- Testez avec le mode démo : `python scripts/run_demo_data.py`

### Streamlit ne se rafraîchit pas
Vérifiez que `streamlit-autorefresh` est installé : `pip install streamlit-autorefresh`

### Erreur de connexion CertStream
Le collector se reconnecte automatiquement toutes les 10 secondes. Si le problème persiste, vérifiez votre connexion internet.

---

## Prochaines améliorations possibles

- [ ] Résolution DNS des domaines détectés (A, MX, NS records)
- [ ] Lookup WHOIS pour les domaines critiques
- [ ] Notifications Telegram/Slack pour les alertes critical
- [ ] Export CSV/JSON des alertes
- [ ] Détection de typosquatting plus avancée (Levenshtein, homoglyphes)
- [ ] Intégration VirusTotal (API gratuite limitée)
- [ ] Carte géographique des issuers
- [ ] Mode multi-pays (Tunisie, Maroc, etc.)
- [ ] Screenshot automatique des domaines actifs (Playwright)
- [ ] API REST pour intégration avec d'autres outils OSINT

---

## Licence

Ce projet est fourni à des fins éducatives et défensives. Utilisez-le de manière responsable.
