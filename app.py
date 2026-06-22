"""DZ Domain Watch — Streamlit Dashboard.

Affiche en temps réel les alertes de certificats SSL/TLS liés à l'Algérie.
Se rafraîchit automatiquement toutes les 5 secondes.

Lancement : streamlit run app.py
"""

import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from dz_domain_watch.db import fetch_events, fetch_stats, get_db_path, init_db

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="DZ Domain Watch",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Auto-refresh every 5 seconds
st_autorefresh(interval=5_000, key="auto_refresh")

# Ensure DB exists
try:
    init_db()
except Exception:
    pass

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .metric-card {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 16px 20px;
        border-left: 4px solid #7c3aed;
        margin-bottom: 8px;
    }
    .risk-critical { color: #ef4444; font-weight: bold; }
    .risk-high     { color: #f97316; font-weight: bold; }
    .risk-medium   { color: #eab308; }
    .risk-low      { color: #22c55e; }
    .alert-banner {
        background: #1e1e2e;
        border: 1px solid #374151;
        border-radius: 8px;
        padding: 16px;
        margin: 8px 0;
    }
    .stDataFrame { font-size: 13px; }
    footer { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("🛡️ DZ Domain Watch")
st.markdown(
    "**Surveillance OSINT défensive des certificats SSL/TLS liés à l'Algérie**  \n"
    "*Données issues des Certificate Transparency logs publics via CertStream.*"
)
st.markdown(
    "> ⚠️ **Avis éthique et légal** : Cet outil est conçu pour de l'OSINT défensif "
    "à partir de sources publiques. Il ne réalise pas d'accès non autorisé, ne contourne "
    "aucune protection, ne teste aucun mot de passe et ne scanne pas d'infrastructures "
    "tierces. Un score élevé indique un signal à vérifier, **pas une preuve de malveillance**."
)

st.divider()

# ---------------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("🔍 Filtres")

    search_text = st.text_input("Recherche texte", placeholder="domaine, issuer, mot-clé…")

    min_score = st.slider("Score minimum", 0, 100, 0, step=5)

    risk_level_filter = st.selectbox(
        "Niveau de risque",
        ["all", "critical", "high", "medium", "low"],
        format_func=lambda x: {
            "all": "Tous",
            "critical": "🔴 Critical",
            "high": "🟠 High",
            "medium": "🟡 Medium",
            "low": "🟢 Low",
        }.get(x, x),
    )

    st.markdown("---")
    st.caption(f"📂 Base : `{get_db_path()}`")
    st.caption("🔄 Rafraîchissement auto : 5s")

# ---------------------------------------------------------------------------
# Fetch data
# ---------------------------------------------------------------------------
stats = fetch_stats()
events = fetch_events(
    min_score=min_score,
    risk_level=risk_level_filter if risk_level_filter != "all" else None,
    search=search_text or None,
    limit=2000,
)

# ---------------------------------------------------------------------------
# KPI row
# ---------------------------------------------------------------------------
k1, k2, k3, k4, k5, k6 = st.columns(6)

with k1:
    st.metric("📋 Total alertes", stats.get("total_events", 0))
with k2:
    st.metric("🌐 Domaines uniques", stats.get("unique_domains", 0))
with k3:
    st.metric("🔴 High / Critical", stats.get("high_critical", 0))
with k4:
    st.metric("📈 Score max", stats.get("max_score", 0))
with k5:
    last = stats.get("last_seen") or "—"
    if last and last != "—":
        try:
            dt = datetime.fromisoformat(last)
            last = dt.strftime("%H:%M:%S")
        except Exception:
            pass
    st.metric("🕐 Dernière alerte", last)
with k6:
    st.metric("⏱️ Dernière heure", stats.get("last_hour", 0))

st.divider()

# ---------------------------------------------------------------------------
# Main content split: table + detail panel
# ---------------------------------------------------------------------------
if not events:
    st.info(
        "Aucune alerte trouvée avec ces filtres.  \n"
        "Lancez le collector : `python -m dz_domain_watch.collector`  \n"
        "Ou injectez des données démo : `python scripts/run_demo_data.py`"
    )
else:
    # Build display dataframe
    df = pd.DataFrame(events)

    # Parse JSON list columns for display
    for col in ["reasons", "matched_brands", "matched_keywords", "matched_suspicious_words"]:
        if col in df.columns:
            df[col] = df[col].apply(
                lambda x: ", ".join(json.loads(x)) if isinstance(x, str) and x else ""
            )

    # Map risk_level to emoji prefix
    level_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    if "risk_level" in df.columns:
        df["risk_level"] = df["risk_level"].apply(
            lambda x: f"{level_emoji.get(x, '')} {x}" if x else x
        )

    if "is_wildcard" in df.columns:
        df["is_wildcard"] = df["is_wildcard"].apply(lambda x: "✓" if x else "")

    # Shorten seen_utc for readability
    if "seen_utc" in df.columns:
        df["seen_utc_display"] = df["seen_utc"].apply(
            lambda x: x[:19].replace("T", " ") if isinstance(x, str) else x
        )

    display_cols = [
        "seen_utc_display",
        "risk_score",
        "risk_level",
        "domain",
        "registered_domain",
        "issuer",
        "tld",
        "is_wildcard",
        "reasons",
    ]
    rename_map = {
        "seen_utc_display": "Vu à (UTC)",
        "risk_score": "Score",
        "risk_level": "Niveau",
        "domain": "Domaine",
        "registered_domain": "Domaine racine",
        "issuer": "Issuer",
        "tld": "TLD",
        "is_wildcard": "Wildcard",
        "reasons": "Raisons",
    }
    available_cols = [c for c in display_cols if c in df.columns]
    df_display = df[available_cols].rename(columns=rename_map)

    # Table
    st.subheader(f"📋 Alertes ({len(df_display)} résultats)")
    st.dataframe(
        df_display,
        use_container_width=True,
        height=400,
        column_config={
            "Score": st.column_config.ProgressColumn(
                "Score",
                min_value=0,
                max_value=100,
                format="%d",
            ),
        },
    )

    st.divider()

    # ---------------------------------------------------------------------------
    # Detail panel — last high/critical alert
    # ---------------------------------------------------------------------------
    st.subheader("🔎 Détail — Dernière alerte haute priorité")

    high_events = [e for e in events if e.get("risk_level") in ("critical", "high")]
    detail_event = high_events[0] if high_events else (events[0] if events else None)

    if detail_event:
        lvl = detail_event.get("risk_level", "low").replace("🔴 ", "").replace("🟠 ", "")
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown(f"**Domaine** : `{detail_event.get('domain', '—')}`")
            st.markdown(f"**Score** : `{detail_event.get('risk_score', 0)} / 100`")
            st.markdown(f"**Niveau** : `{lvl.upper()}`")
            st.markdown(f"**Issuer** : {detail_event.get('issuer', '—')}")
            st.markdown(f"**TLD** : `{detail_event.get('tld', '—')}`")
            st.markdown(f"**Wildcard** : {'Oui' if detail_event.get('is_wildcard') else 'Non'}")
        with col_b:
            st.markdown(f"**Vu le (UTC)** : {detail_event.get('seen_utc', '—')[:19]}")
            st.markdown(f"**Valide du** : {(detail_event.get('not_before_utc') or '—')[:10]}")
            st.markdown(f"**Valide au** : {(detail_event.get('not_after_utc') or '—')[:10]}")
            st.markdown(f"**Source log** : {detail_event.get('source', '—')}")
            cert_link = detail_event.get("cert_link") or ""
            if cert_link:
                st.markdown(f"**Lien CT** : [{cert_link[:60]}…]({cert_link})")
            st.markdown(f"**Fingerprint** : `{(detail_event.get('fingerprint') or '—')[:32]}…`")

        reasons_raw = detail_event.get("reasons", "[]")
        try:
            reasons = json.loads(reasons_raw) if isinstance(reasons_raw, str) else []
        except Exception:
            reasons = []
        if reasons:
            st.markdown("**Raisons détectées :**")
            for r in reasons:
                st.markdown(f"- {r}")

    st.divider()

    # ---------------------------------------------------------------------------
    # Charts
    # ---------------------------------------------------------------------------
    st.subheader("📊 Visualisations")

    df_raw = pd.DataFrame(events)

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("**Distribution des scores de risque**")
        if "risk_score" in df_raw.columns:
            hist_data = df_raw["risk_score"].value_counts().sort_index()
            st.bar_chart(hist_data)

    with chart_col2:
        st.markdown("**Alertes par niveau de risque**")
        if "risk_level" in df_raw.columns:
            level_counts = df_raw["risk_level"].value_counts()
            st.bar_chart(level_counts)

    chart_col3, chart_col4 = st.columns(2)

    with chart_col3:
        st.markdown("**Top Issuers**")
        if "issuer" in df_raw.columns:
            top_issuers = df_raw["issuer"].value_counts().head(10)
            st.bar_chart(top_issuers)

    with chart_col4:
        st.markdown("**Top TLDs**")
        if "tld" in df_raw.columns:
            top_tlds = df_raw["tld"].value_counts().head(10)
            st.bar_chart(top_tlds)

    # Timeline if seen_utc is available
    if "seen_utc" in df_raw.columns:
        st.markdown("**Alertes dans le temps**")
        try:
            df_raw["seen_dt"] = pd.to_datetime(df_raw["seen_utc"], utc=True, errors="coerce")
            df_raw = df_raw.dropna(subset=["seen_dt"])
            df_raw["seen_hour"] = df_raw["seen_dt"].dt.floor("h")
            timeline = df_raw.groupby("seen_hour").size().rename("alertes")
            if not timeline.empty:
                st.line_chart(timeline)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.divider()
st.caption(
    "DZ Domain Watch v1.0 — OSINT défensif — Sources publiques uniquement — "
    "Aucun accès non autorisé — Aucun scan actif"
)
