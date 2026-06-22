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
from dz_domain_watch.geo_db import (
    fetch_campaigns,
    fetch_geo_arcs,
    fetch_geo_clusters,
    fetch_geo_points,
    fetch_geo_stats,
    init_geo_db,
)

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

# Ensure DBs exist
try:
    init_db()
    init_geo_db()
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
    .geo-kpi {
        background: linear-gradient(135deg, #1e1e2e 0%, #2d1b69 100%);
        border-radius: 12px;
        padding: 18px;
        border: 1px solid #4c1d95;
        text-align: center;
    }
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
    "*Données issues des Certificate Transparency logs publics via crt.sh.*"
)
st.markdown(
    "> ⚠️ **Avis éthique et légal** : Cet outil est conçu pour de l'OSINT défensif "
    "à partir de sources publiques. Un score élevé indique un signal à vérifier, "
    "**pas une preuve de malveillance**."
)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_alerts, tab_geo = st.tabs(["📋 Alertes CT", "🌍 Geo Intelligence War Room"])


# ═══════════════════════════════════════════════════════════════════════════
# TAB 1 — Alertes CT
# ═══════════════════════════════════════════════════════════════════════════
with tab_alerts:

    # Sidebar filters (only active in this tab logically, but sidebar is global)
    with st.sidebar:
        st.header("🔍 Filtres Alertes")

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

    # Fetch data
    stats = fetch_stats()
    events = fetch_events(
        min_score=min_score,
        risk_level=risk_level_filter if risk_level_filter != "all" else None,
        search=search_text or None,
        limit=2000,
    )

    # KPI row
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

    if not events:
        st.info(
            "Aucune alerte trouvée avec ces filtres.  \n"
            "Lancez le collector : `python -m dz_domain_watch.collector`  \n"
            "Ou injectez des données démo : `python scripts/run_demo_data.py`"
        )
    else:
        # Build display dataframe
        df = pd.DataFrame(events)

        for col in ["reasons", "matched_brands", "matched_keywords", "matched_suspicious_words"]:
            if col in df.columns:
                df[col] = df[col].apply(
                    lambda x: ", ".join(json.loads(x)) if isinstance(x, str) and x else ""
                )

        level_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        if "risk_level" in df.columns:
            df["risk_level"] = df["risk_level"].apply(
                lambda x: f"{level_emoji.get(x, '')} {x}" if x else x
            )

        if "is_wildcard" in df.columns:
            df["is_wildcard"] = df["is_wildcard"].apply(lambda x: "✓" if x else "")

        if "seen_utc" in df.columns:
            df["seen_utc_display"] = df["seen_utc"].apply(
                lambda x: x[:19].replace("T", " ") if isinstance(x, str) else x
            )

        display_cols = [
            "seen_utc_display", "risk_score", "risk_level", "domain",
            "registered_domain", "issuer", "tld", "is_wildcard", "reasons",
        ]
        rename_map = {
            "seen_utc_display": "Vu à (UTC)", "risk_score": "Score",
            "risk_level": "Niveau", "domain": "Domaine",
            "registered_domain": "Domaine racine", "issuer": "Issuer",
            "tld": "TLD", "is_wildcard": "Wildcard", "reasons": "Raisons",
        }
        available_cols = [c for c in display_cols if c in df.columns]
        df_display = df[available_cols].rename(columns=rename_map)

        st.subheader(f"📋 Alertes ({len(df_display)} résultats)")
        st.dataframe(
            df_display,
            use_container_width=True,
            height=400,
            column_config={
                "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
            },
        )

        st.divider()

        # Detail panel
        st.subheader("🔎 Détail — Dernière alerte haute priorité")
        high_events = [e for e in events if e.get("risk_level") in ("critical", "high")]
        detail_event = high_events[0] if high_events else (events[0] if events else None)

        if detail_event:
            lvl = detail_event.get("risk_level", "low")
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

        # Charts
        st.subheader("📊 Visualisations")
        df_raw = pd.DataFrame(events)
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.markdown("**Distribution des scores de risque**")
            if "risk_score" in df_raw.columns:
                st.bar_chart(df_raw["risk_score"].value_counts().sort_index())
        with chart_col2:
            st.markdown("**Alertes par niveau de risque**")
            if "risk_level" in df_raw.columns:
                st.bar_chart(df_raw["risk_level"].value_counts())

        chart_col3, chart_col4 = st.columns(2)
        with chart_col3:
            st.markdown("**Top Issuers**")
            if "issuer" in df_raw.columns:
                st.bar_chart(df_raw["issuer"].value_counts().head(10))
        with chart_col4:
            st.markdown("**Top TLDs**")
            if "tld" in df_raw.columns:
                st.bar_chart(df_raw["tld"].value_counts().head(10))

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

    st.divider()
    st.caption(
        "DZ Domain Watch v2.0 — OSINT défensif — Sources publiques uniquement — "
        "Aucun accès non autorisé — Aucun scan actif"
    )


# ═══════════════════════════════════════════════════════════════════════════
# TAB 2 — Geo Intelligence War Room
# ═══════════════════════════════════════════════════════════════════════════
with tab_geo:
    st.markdown(
        "## 🌍 Geo Intelligence War Room\n"
        "Cartographie des infrastructures d'hébergement des domaines malveillants ciblant l'Algérie."
    )

    # Lazy import map renderers
    try:
        from dz_domain_watch.maps import (
            arc_map,
            cluster_bubble_map,
            folium_analyst_map,
            heatmap,
            hexagon_map,
            scatter_map,
        )
        _maps_ok = True
    except ImportError as e:
        _maps_ok = False
        st.error(f"Modules cartographiques non disponibles : {e}. Lance `pip install pydeck folium streamlit-folium`")

    # Fetch geo data
    geo_stats = fetch_geo_stats()
    campaigns_list = ["Toutes"] + fetch_campaigns()

    # ── Geo KPIs ─────────────────────────────────────────────────────────
    gk1, gk2, gk3, gk4, gk5 = st.columns(5)
    with gk1:
        st.metric("🌐 IPs tracées", geo_stats.get("total_ips", 0))
    with gk2:
        st.metric("🗺️ Pays impliqués", geo_stats.get("countries_count", 0))
    with gk3:
        st.metric("🎯 Campagnes", geo_stats.get("campaigns_count", 0))
    with gk4:
        st.metric("🏢 Hébergeurs", geo_stats.get("providers_count", 0))
    with gk5:
        st.metric("🔥 Score max", geo_stats.get("max_score", 0))

    if geo_stats.get("total_ips", 0) == 0:
        st.warning(
            "Aucune donnée géo disponible.  \n"
            "Injecte les données démo : `python scripts/run_geo_demo_data.py`"
        )
        st.stop()

    st.divider()

    # ── Campaign filter + Map mode selector ──────────────────────────────
    col_camp, col_mode = st.columns([2, 3])
    with col_camp:
        selected_campaign = st.selectbox("🎯 Campagne", campaigns_list)
    with col_mode:
        map_mode = st.radio(
            "🗺️ Vue cartographique",
            ["Scatter (IPs)", "Arcs (Algérie → Serveurs)", "Heatmap", "Hexagones", "Bulles Campagnes", "Analyst (Folium)"],
            horizontal=True,
        )

    # Load data according to filter
    cam_filter = None if selected_campaign == "Toutes" else selected_campaign
    geo_points = fetch_geo_points(campaign=cam_filter)
    geo_arcs   = fetch_geo_arcs(campaign=cam_filter)
    geo_clusters = fetch_geo_clusters()

    st.markdown(f"**{len(geo_points)} point(s) géo** | **{len(geo_arcs)} arc(s)** | **{len(geo_clusters)} cluster(s)**")

    # ── Map rendering ────────────────────────────────────────────────────
    if _maps_ok:
        if map_mode == "Scatter (IPs)":
            deck = scatter_map(geo_points)
            if deck:
                import pydeck as pdk
                st.pydeck_chart(deck, use_container_width=True)
            else:
                st.info("Pas de données pour cette vue.")

        elif map_mode == "Arcs (Algérie → Serveurs)":
            deck = arc_map(geo_arcs)
            if deck:
                import pydeck as pdk
                st.pydeck_chart(deck, use_container_width=True)
                st.caption("🔵 Source = Algérie | Couleur cible = niveau de risque")
            else:
                st.info("Pas de données pour cette vue.")

        elif map_mode == "Heatmap":
            deck = heatmap(geo_points)
            if deck:
                import pydeck as pdk
                st.pydeck_chart(deck, use_container_width=True)

        elif map_mode == "Hexagones":
            deck = hexagon_map(geo_points)
            if deck:
                import pydeck as pdk
                st.pydeck_chart(deck, use_container_width=True)
                st.caption("Hauteur des colonnes = concentration de domaines malveillants")

        elif map_mode == "Bulles Campagnes":
            deck = cluster_bubble_map(geo_clusters)
            if deck:
                import pydeck as pdk
                st.pydeck_chart(deck, use_container_width=True)

        elif map_mode == "Analyst (Folium)":
            try:
                from streamlit_folium import st_folium
                fmap = folium_analyst_map(geo_points)
                if fmap:
                    st_folium(fmap, use_container_width=True, height=520)
                else:
                    st.info("Pas de données pour cette vue.")
            except ImportError:
                st.error("streamlit-folium non installé. Lance `pip install streamlit-folium`")

    st.divider()

    # ── Campaign Intelligence Panels ─────────────────────────────────────
    st.subheader("🎯 Intelligence par Campagne")

    clusters = fetch_geo_clusters()
    if clusters:
        for cl in clusters:
            risk_colours = {
                "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"
            }
            icon = risk_colours.get(cl.get("risk_level", "low"), "⚪")
            with st.expander(f"{icon} **{cl['campaign']}** — {cl['count']} domaines | Score max: {cl['risk_max']}"):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Niveau de risque** : `{cl['risk_level'].upper()}`")
                    st.markdown(f"**Score maximum** : `{cl['risk_max']}/100`")
                    countries = cl.get("countries", [])
                    st.markdown(f"**Pays hébergeurs** : {', '.join(countries) if countries else '—'}")
                with c2:
                    domains = cl.get("domains", [])
                    if domains:
                        st.markdown("**Domaines détectés :**")
                        for d in domains:
                            st.markdown(f"- `{d}`")

    st.divider()

    # ── Geo Data Table ────────────────────────────────────────────────────
    st.subheader("📊 Tableau des points géo")
    if geo_points:
        df_geo = pd.DataFrame(geo_points)
        display_geo_cols = ["domain", "ip", "city", "country", "hosting_provider", "asn", "campaign", "risk_score", "risk_level"]
        available_geo = [c for c in display_geo_cols if c in df_geo.columns]
        rename_geo = {
            "domain": "Domaine", "ip": "IP", "city": "Ville",
            "country": "Pays", "hosting_provider": "Hébergeur",
            "asn": "ASN", "campaign": "Campagne",
            "risk_score": "Score", "risk_level": "Niveau",
        }
        st.dataframe(
            df_geo[available_geo].rename(columns=rename_geo),
            use_container_width=True,
            height=300,
            column_config={
                "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
            },
        )

    st.divider()

    # ── Hosting provider breakdown ────────────────────────────────────────
    st.subheader("🏢 Répartition par hébergeur")
    if geo_points:
        df_geo_full = pd.DataFrame(geo_points)
        col_h1, col_h2 = st.columns(2)
        with col_h1:
            if "hosting_provider" in df_geo_full.columns:
                st.markdown("**Domaines par hébergeur**")
                st.bar_chart(df_geo_full["hosting_provider"].value_counts())
        with col_h2:
            if "country" in df_geo_full.columns:
                st.markdown("**Domaines par pays**")
                st.bar_chart(df_geo_full["country"].value_counts())

    st.caption(
        "🌍 Geo Intelligence War Room — DZ Domain Watch v2.0 — "
        "Données OSINT défensives — Sources CT publiques uniquement"
    )
