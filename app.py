"""DZ Domain Watch — Streamlit Dashboard v2.1.

Onglets :
  1. 📋 Alertes CT       — tableau complet des certificats détectés
  2. 🟢 Domaines Actifs  — uniquement les domaines joignables en ligne (vérif HTTP live)
  3. 🌍 Geo War Room     — cartographie des infrastructures phishing

Lancement : streamlit run app.py
"""

import json
import threading
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

st_autorefresh(interval=5_000, key="auto_refresh")

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
    .risk-critical { color: #ef4444; font-weight: bold; }
    .risk-high     { color: #f97316; font-weight: bold; }
    .risk-medium   { color: #eab308; }
    .risk-low      { color: #22c55e; }
    .stDataFrame { font-size: 13px; }
    footer { visibility: hidden; }
    div[data-testid="metric-container"] {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 12px 16px;
        border-left: 4px solid #7c3aed;
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
    "**Surveillance OSINT défensive des certificats SSL/TLS liés à l'Algérie** — "
    "Source : Certificate Transparency logs (crt.sh)  \n"
    "> ⚠️ Un score élevé = signal à vérifier manuellement. Pas une preuve de malveillance."
)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_alerts, tab_live, tab_geo = st.tabs([
    "📋 Alertes CT",
    "🟢 Domaines Actifs (vérif live)",
    "🌍 Geo Intelligence War Room",
])


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
_LEVEL_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def _parse_json_col(val):
    if isinstance(val, list):
        return ", ".join(val)
    if isinstance(val, str) and val:
        try:
            return ", ".join(json.loads(val))
        except Exception:
            return val
    return ""


def _build_full_df(events: list[dict]) -> pd.DataFrame:
    """Turn raw DB rows into a fully-labelled display DataFrame."""
    if not events:
        return pd.DataFrame()
    df = pd.DataFrame(events)

    # Parse JSON list columns
    for col in ["reasons", "matched_brands", "matched_keywords", "matched_suspicious_words"]:
        if col in df.columns:
            df[col] = df[col].apply(_parse_json_col)

    # Risk level with emoji
    if "risk_level" in df.columns:
        df["risk_level"] = df["risk_level"].apply(
            lambda x: f"{_LEVEL_EMOJI.get(x,'')} {x}" if x else x
        )

    # Wildcard
    if "is_wildcard" in df.columns:
        df["is_wildcard"] = df["is_wildcard"].apply(lambda x: "✅ Oui" if x else "Non")

    # Dates
    for dt_col in ["seen_utc", "not_before_utc", "not_after_utc", "inserted_at_utc"]:
        if dt_col in df.columns:
            df[dt_col] = df[dt_col].apply(
                lambda x: x[:19].replace("T", " ") if isinstance(x, str) else x
            )

    col_order = [
        "seen_utc", "inserted_at_utc",
        "risk_score", "risk_level",
        "domain", "registered_domain", "tld",
        "is_wildcard",
        "issuer",
        "not_before_utc", "not_after_utc",
        "source", "cert_link",
        "matched_brands", "matched_keywords", "matched_suspicious_words",
        "reasons",
        "fingerprint",
    ]
    available = [c for c in col_order if c in df.columns]
    df = df[available]

    rename = {
        "seen_utc": "Vu à (UTC)",
        "inserted_at_utc": "Inséré à (UTC)",
        "risk_score": "Score",
        "risk_level": "Niveau",
        "domain": "Domaine",
        "registered_domain": "Domaine racine",
        "tld": "TLD",
        "is_wildcard": "Wildcard",
        "issuer": "Émetteur cert",
        "not_before_utc": "Valide depuis",
        "not_after_utc": "Expire le",
        "source": "Source CT",
        "cert_link": "Lien CT",
        "matched_brands": "Marques détectées",
        "matched_keywords": "Mots-clés pays",
        "matched_suspicious_words": "Mots suspects",
        "reasons": "Raisons",
        "fingerprint": "Fingerprint",
    }
    return df.rename(columns=rename)


# ═══════════════════════════════════════════════════════════════════════════
# TAB 1 — Alertes CT (tableau complet)
# ═══════════════════════════════════════════════════════════════════════════
with tab_alerts:
    with st.sidebar:
        st.header("🔍 Filtres")
        search_text = st.text_input("Recherche", placeholder="domaine, issuer, marque…")
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
        st.caption(f"📂 DB : `{get_db_path()}`")
        st.caption("🔄 Refresh : 5s")

    stats = fetch_stats()
    events = fetch_events(
        min_score=min_score,
        risk_level=risk_level_filter if risk_level_filter != "all" else None,
        search=search_text or None,
        limit=2000,
    )

    # KPIs
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    with k1:
        st.metric("📋 Total", stats.get("total_events", 0))
    with k2:
        st.metric("🌐 Domaines uniques", stats.get("unique_domains", 0))
    with k3:
        st.metric("🔴 High + Critical", stats.get("high_critical", 0))
    with k4:
        st.metric("📈 Score max", stats.get("max_score", 0))
    with k5:
        last = stats.get("last_seen") or "—"
        if last and last != "—":
            try:
                last = datetime.fromisoformat(last).strftime("%H:%M:%S")
            except Exception:
                pass
        st.metric("🕐 Dernière alerte", last)
    with k6:
        st.metric("⏱️ Dernière heure", stats.get("last_hour", 0))

    st.divider()

    if not events:
        st.info(
            "Aucune alerte. Lance : `python -m dz_domain_watch.collector`  \n"
            "Ou données démo : `python scripts/run_demo_data.py`"
        )
    else:
        df_display = _build_full_df(events)

        st.subheader(f"📋 {len(events)} alerte(s) — tableau complet")
        st.dataframe(
            df_display,
            use_container_width=True,
            height=500,
            column_config={
                "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
                "Lien CT": st.column_config.LinkColumn("Lien CT"),
            },
        )

        st.divider()

        # Panneau détail — dernière alerte critique/high
        st.subheader("🔎 Détail — dernière alerte haute priorité")
        high_events = [e for e in events if e.get("risk_level") in ("critical", "high")]
        detail = high_events[0] if high_events else (events[0] if events else None)
        if detail:
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown(f"**Domaine** : `{detail.get('domain','—')}`")
                st.markdown(f"**Domaine racine** : `{detail.get('registered_domain','—')}`")
                st.markdown(f"**TLD** : `{detail.get('tld','—')}`")
                st.markdown(f"**Wildcard** : {'✅ Oui' if detail.get('is_wildcard') else 'Non'}")
                st.markdown(f"**Score** : `{detail.get('risk_score',0)} / 100`")
                lvl = detail.get('risk_level','low')
                st.markdown(f"**Niveau** : `{lvl.upper()}`")
            with c2:
                st.markdown(f"**Émetteur** : {detail.get('issuer','—')}")
                st.markdown(f"**Source CT** : {detail.get('source','—')}")
                cert_link = detail.get("cert_link") or ""
                if cert_link:
                    st.markdown(f"**Lien CT** : [Voir le certificat]({cert_link})")
                st.markdown(f"**Vu le** : {(detail.get('seen_utc') or '—')[:19]}")
                st.markdown(f"**Valide depuis** : {(detail.get('not_before_utc') or '—')[:10]}")
                st.markdown(f"**Expire le** : {(detail.get('not_after_utc') or '—')[:10]}")
            with c3:
                for field, label in [
                    ("matched_brands", "🏢 Marques"),
                    ("matched_keywords", "🇩🇿 Mots-clés"),
                    ("matched_suspicious_words", "⚠️ Mots suspects"),
                ]:
                    val = _parse_json_col(detail.get(field, "[]"))
                    if val:
                        st.markdown(f"**{label}** : {val}")
                reasons_raw = detail.get("reasons", "[]")
                try:
                    reasons = json.loads(reasons_raw) if isinstance(reasons_raw, str) else []
                except Exception:
                    reasons = []
                if reasons:
                    st.markdown("**Raisons :**")
                    for r in reasons:
                        st.markdown(f"- {r}")

        st.divider()

        # Charts
        st.subheader("📊 Statistiques")
        df_raw = pd.DataFrame(events)
        cc1, cc2, cc3, cc4 = st.columns(4)
        with cc1:
            st.markdown("**Scores**")
            if "risk_score" in df_raw.columns:
                st.bar_chart(df_raw["risk_score"].value_counts().sort_index())
        with cc2:
            st.markdown("**Niveaux**")
            if "risk_level" in df_raw.columns:
                st.bar_chart(df_raw["risk_level"].value_counts())
        with cc3:
            st.markdown("**Top Issuers**")
            if "issuer" in df_raw.columns:
                st.bar_chart(df_raw["issuer"].value_counts().head(8))
        with cc4:
            st.markdown("**Top TLDs**")
            if "tld" in df_raw.columns:
                st.bar_chart(df_raw["tld"].value_counts().head(8))

        if "seen_utc" in df_raw.columns:
            st.markdown("**Timeline**")
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
    st.caption("DZ Domain Watch v2.1 — OSINT défensif — Sources CT publiques — Aucun scan actif")


# ═══════════════════════════════════════════════════════════════════════════
# TAB 2 — Domaines Actifs (vérification live HTTP)
# ═══════════════════════════════════════════════════════════════════════════
with tab_live:
    st.markdown(
        "## 🟢 Domaines Actifs — Vérification en ligne\n"
        "Teste chaque domaine détecté avec une requête HTTP HEAD pour savoir "
        "s'il est **réellement en ligne** au moment de la vérification."
    )

    events_for_live = fetch_events(min_score=0, limit=500)

    if not events_for_live:
        st.info("Aucune alerte dans la base. Lance d'abord le collecteur ou les données démo.")
    else:
        col_ctrl1, col_ctrl2, col_ctrl3 = st.columns([2, 2, 3])
        with col_ctrl1:
            live_min_score = st.slider("Score minimum (live)", 0, 100, 40, step=5, key="live_score")
        with col_ctrl2:
            live_max_domains = st.number_input("Nb max de domaines à tester", 5, 200, 50, step=5)
        with col_ctrl3:
            st.markdown("")
            st.markdown("")
            run_check = st.button("🔍 Lancer la vérification live", type="primary")

        # Filter candidates
        candidates = [
            e for e in events_for_live
            if e.get("risk_score", 0) >= live_min_score
        ][:int(live_max_domains)]

        st.info(
            f"**{len(candidates)}** domaine(s) sélectionné(s) pour vérification "
            f"(score ≥ {live_min_score}).  \n"
            "⏱️ La vérification prend ~5-15 secondes selon le nombre de domaines."
        )

        if run_check and candidates:
            from dz_domain_watch.live_check import bulk_check

            domains_to_check = [e["domain"] for e in candidates]

            progress_bar = st.progress(0, text="Vérification en cours…")
            status_text = st.empty()

            # Run check with progress
            results_container: dict = {}
            check_done = threading.Event()

            def _run():
                results_container.update(bulk_check(domains_to_check, max_workers=15))
                check_done.set()

            t = threading.Thread(target=_run, daemon=True)
            t.start()

            checked = 0
            while not check_done.is_set():
                n = len(results_container)
                if n > checked:
                    checked = n
                    pct = min(checked / len(domains_to_check), 1.0)
                    progress_bar.progress(pct, text=f"Vérifié {checked}/{len(domains_to_check)}…")
                import time
                time.sleep(0.3)

            t.join()
            progress_bar.progress(1.0, text="✅ Vérification terminée !")
            status_text.empty()

            # Merge results with event data
            live_rows = []
            dead_rows = []
            for event in candidates:
                dom = event["domain"]
                chk = results_container.get(dom, {})
                is_live = chk.get("is_live", False)
                status_code = chk.get("status_code")
                server = chk.get("server") or ""
                redirect = chk.get("redirect_url") or ""
                err = chk.get("error") or ""
                checked_at = chk.get("checked_at", "")[:19].replace("T", " ")

                row = {
                    "🔗 Statut": "🟢 EN LIGNE" if is_live else "🔴 HORS LIGNE",
                    "HTTP": status_code or "—",
                    "Score": event.get("risk_score", 0),
                    "Niveau": f"{_LEVEL_EMOJI.get(event.get('risk_level','low'),'')} {event.get('risk_level','')}",
                    "Domaine": dom,
                    "Domaine racine": event.get("registered_domain", ""),
                    "TLD": event.get("tld", ""),
                    "Wildcard": "✅" if event.get("is_wildcard") else "",
                    "Émetteur cert": event.get("issuer", ""),
                    "Valide depuis": (event.get("not_before_utc") or "")[:10],
                    "Expire le": (event.get("not_after_utc") or "")[:10],
                    "Serveur web": server,
                    "Redirection": redirect[:60] if redirect else "",
                    "Marques": _parse_json_col(event.get("matched_brands", "[]")),
                    "Mots suspects": _parse_json_col(event.get("matched_suspicious_words", "[]")),
                    "Raisons": _parse_json_col(event.get("reasons", "[]")),
                    "Source CT": event.get("source", ""),
                    "Lien cert": event.get("cert_link") or "",
                    "Vu à (UTC)": (event.get("seen_utc") or "")[:19].replace("T", " "),
                    "Vérifié à": checked_at,
                    "Erreur": err[:80] if err else "",
                }
                if is_live:
                    live_rows.append(row)
                else:
                    dead_rows.append(row)

            # Summary
            s1, s2, s3 = st.columns(3)
            with s1:
                st.metric("🟢 En ligne", len(live_rows))
            with s2:
                st.metric("🔴 Hors ligne / inaccessible", len(dead_rows))
            with s3:
                pct_live = round(len(live_rows) / len(candidates) * 100) if candidates else 0
                st.metric("📊 Taux de réponse", f"{pct_live}%")

            if live_rows:
                st.subheader(f"🟢 {len(live_rows)} domaine(s) ACTIFS et JOIGNABLES")
                st.markdown(
                    "⚠️ Ces domaines répondent à une requête HTTP — "
                    "ils sont **réellement opérationnels** au moment du test."
                )
                df_live = pd.DataFrame(live_rows)
                st.dataframe(
                    df_live,
                    use_container_width=True,
                    height=450,
                    column_config={
                        "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
                        "Lien cert": st.column_config.LinkColumn("Lien cert"),
                    },
                )

                # Export
                csv = df_live.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇️ Exporter les domaines actifs (CSV)",
                    csv,
                    file_name=f"dz_watch_live_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                )
            else:
                st.success("Aucun domaine actif détecté parmi les candidats testés.")

            if dead_rows:
                with st.expander(f"🔴 {len(dead_rows)} domaine(s) hors ligne / inaccessibles"):
                    st.dataframe(pd.DataFrame(dead_rows), use_container_width=True, height=300)

        elif not run_check:
            st.markdown(
                "👆 Clique sur **Lancer la vérification live** pour tester les domaines."
            )

    st.divider()
    st.caption(
        "Vérification passive via requête HTTP HEAD — aucun scan, aucune interaction avec le contenu des sites."
    )


# ═══════════════════════════════════════════════════════════════════════════
# TAB 3 — Geo Intelligence War Room
# ═══════════════════════════════════════════════════════════════════════════
with tab_geo:
    st.markdown(
        "## 🌍 Geo Intelligence War Room\n"
        "Cartographie des infrastructures d'hébergement des domaines phishing ciblant l'Algérie."
    )

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
        st.error(f"Modules cartographiques indisponibles : {e}")

    geo_stats = fetch_geo_stats()
    campaigns_list = ["Toutes"] + fetch_campaigns()

    # Geo KPIs
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
            "Aucune donnée géo. Injecte les données démo :  \n"
            "`python scripts/run_geo_demo_data.py`"
        )
    else:
        st.divider()

        col_camp, col_mode = st.columns([2, 4])
        with col_camp:
            selected_campaign = st.selectbox("🎯 Campagne", campaigns_list)
        with col_mode:
            map_mode = st.radio(
                "🗺️ Vue",
                ["Scatter (IPs)", "Arcs (DZ → Serveurs)", "Heatmap", "Hexagones 3D", "Bulles Campagnes", "Analyst Détail (Folium)"],
                horizontal=True,
            )

        cam_filter = None if selected_campaign == "Toutes" else selected_campaign
        geo_points  = fetch_geo_points(campaign=cam_filter)
        geo_arcs    = fetch_geo_arcs(campaign=cam_filter)
        geo_clusters = fetch_geo_clusters()

        st.caption(f"**{len(geo_points)}** point(s) | **{len(geo_arcs)}** arc(s) | **{len(geo_clusters)}** cluster(s)")

        if _maps_ok:
            import pydeck as pdk

            if map_mode == "Scatter (IPs)":
                deck = scatter_map(geo_points)
                if deck:
                    st.pydeck_chart(deck, use_container_width=True)
                    st.caption("Un point = une IP hébergeant un domaine suspect. Couleur = niveau de risque.")

            elif map_mode == "Arcs (DZ → Serveurs)":
                deck = arc_map(geo_arcs)
                if deck:
                    st.pydeck_chart(deck, use_container_width=True)
                    st.caption("🔵 Source = Algérie (cible des attaques) | Extrémité colorée = serveur d'hébergement")

            elif map_mode == "Heatmap":
                deck = heatmap(geo_points)
                if deck:
                    st.pydeck_chart(deck, use_container_width=True)
                    st.caption("Intensité = densité de domaines malveillants pondérée par score de risque")

            elif map_mode == "Hexagones 3D":
                deck = hexagon_map(geo_points)
                if deck:
                    st.pydeck_chart(deck, use_container_width=True)
                    st.caption("Hauteur des colonnes = concentration de domaines suspects dans la zone")

            elif map_mode == "Bulles Campagnes":
                deck = cluster_bubble_map(geo_clusters)
                if deck:
                    st.pydeck_chart(deck, use_container_width=True)

            elif map_mode == "Analyst Détail (Folium)":
                try:
                    from streamlit_folium import st_folium
                    fmap = folium_analyst_map(geo_points)
                    if fmap:
                        st_folium(fmap, use_container_width=True, height=540)
                    else:
                        st.info("Pas de données pour cette vue.")
                except ImportError:
                    st.error("streamlit-folium non installé : `pip install streamlit-folium`")

        st.divider()

        # Intelligence panels per campaign
        st.subheader("🎯 Intelligence par Campagne")
        clusters = fetch_geo_clusters()
        _risk_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        for cl in clusters:
            icon = _risk_icon.get(cl.get("risk_level", "low"), "⚪")
            with st.expander(
                f"{icon} **{cl['campaign']}** — {cl['count']} domaines | Score max : {cl['risk_max']}"
            ):
                cx1, cx2 = st.columns(2)
                with cx1:
                    st.markdown(f"**Niveau** : `{cl['risk_level'].upper()}`")
                    st.markdown(f"**Score max** : `{cl['risk_max']}/100`")
                    countries = cl.get("countries", [])
                    st.markdown(f"**Pays hébergeurs** : {', '.join(countries) if countries else '—'}")
                with cx2:
                    domains = cl.get("domains", [])
                    if domains:
                        st.markdown("**Domaines :**")
                        for d in domains:
                            st.markdown(f"- `{d}`")

        st.divider()

        # Geo table
        st.subheader("📊 Tableau détaillé des points géo")
        if geo_points:
            df_geo = pd.DataFrame(geo_points)
            geo_cols = [
                "domain", "ip", "city", "country", "hosting_provider",
                "asn", "org", "campaign", "risk_score", "risk_level", "seen_utc",
            ]
            avail_geo = [c for c in geo_cols if c in df_geo.columns]
            rename_geo = {
                "domain": "Domaine", "ip": "IP", "city": "Ville",
                "country": "Pays", "hosting_provider": "Hébergeur",
                "asn": "ASN", "org": "Organisation",
                "campaign": "Campagne", "risk_score": "Score",
                "risk_level": "Niveau", "seen_utc": "Vu à (UTC)",
            }
            st.dataframe(
                df_geo[avail_geo].rename(columns=rename_geo),
                use_container_width=True,
                height=320,
                column_config={
                    "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
                },
            )

        # Hosting breakdown
        if geo_points:
            st.subheader("🏢 Répartition par hébergeur et pays")
            df_gf = pd.DataFrame(geo_points)
            hc1, hc2 = st.columns(2)
            with hc1:
                if "hosting_provider" in df_gf.columns:
                    st.markdown("**Par hébergeur**")
                    st.bar_chart(df_gf["hosting_provider"].value_counts())
            with hc2:
                if "country" in df_gf.columns:
                    st.markdown("**Par pays**")
                    st.bar_chart(df_gf["country"].value_counts())

    st.divider()
    st.caption(
        "🌍 Geo Intelligence War Room — DZ Domain Watch v2.1 — "
        "OSINT défensif — Sources CT publiques uniquement"
    )
