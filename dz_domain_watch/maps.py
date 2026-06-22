"""Map rendering helpers for the Geo Intelligence War Room.

Returns pydeck.Deck objects or folium.Map objects ready for Streamlit.
"""

from typing import Optional

import pandas as pd

try:
    import pydeck as pdk
    _PYDECK_OK = True
except ImportError:
    _PYDECK_OK = False

try:
    import folium
    _FOLIUM_OK = True
except ImportError:
    _FOLIUM_OK = False


# Colour palette per risk level  (RGBA arrays for PyDeck)
_RISK_COLOUR = {
    "critical": [239, 68, 68, 220],
    "high":     [249, 115, 22, 200],
    "medium":   [234, 179, 8, 180],
    "low":      [34, 197, 94, 160],
}

_RISK_HEX = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#22c55e",
}

_DARK_MAP_STYLE = "mapbox://styles/mapbox/dark-v10"
_LIGHT_MAP_STYLE = "mapbox://styles/mapbox/light-v10"


def _to_df(points: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(points)
    if df.empty:
        return df
    df["color"] = df["risk_level"].apply(lambda x: _RISK_COLOUR.get(x, [100, 100, 100, 180]))
    df["radius"] = df["risk_score"].apply(lambda x: max(30_000, int(x) * 800))
    return df


def scatter_map(points: list[dict]) -> Optional[object]:
    """Scatterplot layer — one dot per IP."""
    if not _PYDECK_OK or not points:
        return None

    df = _to_df(points)

    layer = pdk.Layer(
        "ScatterplotLayer",
        data=df,
        get_position=["lon", "lat"],
        get_color="color",
        get_radius="radius",
        pickable=True,
        opacity=0.8,
        stroked=True,
        filled=True,
        line_width_min_pixels=1,
    )

    view = pdk.ViewState(latitude=35.0, longitude=15.0, zoom=2, pitch=0)

    return pdk.Deck(
        layers=[layer],
        initial_view_state=view,
        map_style=_DARK_MAP_STYLE,
        tooltip={
            "html": (
                "<b>{domain}</b><br/>"
                "IP: {ip}<br/>"
                "Ville: {city}, {country}<br/>"
                "Score: {risk_score} ({risk_level})<br/>"
                "Hébergeur: {hosting_provider}<br/>"
                "Campagne: {campaign}"
            ),
            "style": {"color": "white", "background": "#1e1e2e", "padding": "8px"},
        },
    )


def arc_map(arcs: list[dict]) -> Optional[object]:
    """Arc layer — arrows from Algiers to server locations."""
    if not _PYDECK_OK or not arcs:
        return None

    df = pd.DataFrame(arcs)
    df["color"] = df["risk_level"].apply(lambda x: _RISK_COLOUR.get(x, [100, 100, 100, 200]))

    layer = pdk.Layer(
        "ArcLayer",
        data=df,
        get_source_position=["src_lon", "src_lat"],
        get_target_position=["dst_lon", "dst_lat"],
        get_source_color=[0, 200, 255, 180],
        get_target_color="color",
        get_width=3,
        pickable=True,
        auto_highlight=True,
    )

    view = pdk.ViewState(latitude=40.0, longitude=10.0, zoom=2, pitch=30)

    return pdk.Deck(
        layers=[layer],
        initial_view_state=view,
        map_style=_DARK_MAP_STYLE,
        tooltip={
            "html": (
                "<b>{domain}</b><br/>"
                "{src_city} → {dst_city}<br/>"
                "Score: {risk_score} | Campagne: {campaign}"
            ),
            "style": {"color": "white", "background": "#1e1e2e", "padding": "8px"},
        },
    )


def heatmap(points: list[dict]) -> Optional[object]:
    """Heatmap layer weighted by risk score."""
    if not _PYDECK_OK or not points:
        return None

    df = pd.DataFrame(points)
    df["weight"] = df["risk_score"].apply(lambda x: int(x) / 100.0)

    layer = pdk.Layer(
        "HeatmapLayer",
        data=df,
        get_position=["lon", "lat"],
        get_weight="weight",
        radiusPixels=60,
        intensity=1,
        threshold=0.05,
    )

    view = pdk.ViewState(latitude=35.0, longitude=15.0, zoom=2)

    return pdk.Deck(
        layers=[layer],
        initial_view_state=view,
        map_style=_DARK_MAP_STYLE,
    )


def hexagon_map(points: list[dict]) -> Optional[object]:
    """Hexagon aggregation layer."""
    if not _PYDECK_OK or not points:
        return None

    df = pd.DataFrame(points)

    layer = pdk.Layer(
        "HexagonLayer",
        data=df,
        get_position=["lon", "lat"],
        radius=100_000,
        elevation_scale=5000,
        elevation_range=[0, 3000],
        pickable=True,
        extruded=True,
        coverage=0.9,
        color_range=[
            [1, 152, 189, 180],
            [73, 227, 206, 180],
            [216, 254, 181, 180],
            [254, 237, 177, 180],
            [254, 173, 84, 180],
            [209, 55, 78, 200],
        ],
    )

    view = pdk.ViewState(latitude=35.0, longitude=15.0, zoom=2, pitch=40, bearing=0)

    return pdk.Deck(
        layers=[layer],
        initial_view_state=view,
        map_style=_DARK_MAP_STYLE,
        tooltip={"html": "<b>Concentration</b><br/>Nb domaines: {elevationValue}"},
    )


def cluster_bubble_map(clusters: list[dict]) -> Optional[object]:
    """Bubble map — one bubble per campaign cluster, sized by count."""
    if not _PYDECK_OK or not clusters:
        return None

    df = pd.DataFrame(clusters)
    df["color"] = df["risk_level"].apply(lambda x: _RISK_COLOUR.get(x, [100, 100, 100, 180]))
    df["radius"] = df["count"].apply(lambda x: max(100_000, int(x) * 150_000))

    layer = pdk.Layer(
        "ScatterplotLayer",
        data=df,
        get_position=["center_lon", "center_lat"],
        get_color="color",
        get_radius="radius",
        pickable=True,
        opacity=0.7,
    )

    view = pdk.ViewState(latitude=40.0, longitude=10.0, zoom=2)

    return pdk.Deck(
        layers=[layer],
        initial_view_state=view,
        map_style=_DARK_MAP_STYLE,
        tooltip={
            "html": (
                "<b>Campagne: {campaign}</b><br/>"
                "Nb domaines: {count}<br/>"
                "Score max: {risk_max}<br/>"
                "Niveau: {risk_level}"
            ),
            "style": {"color": "white", "background": "#1e1e2e", "padding": "8px"},
        },
    )


def folium_analyst_map(points: list[dict]) -> Optional[object]:
    """Detailed Folium map with popups for analyst drilldown."""
    if not _FOLIUM_OK or not points:
        return None

    m = folium.Map(
        location=[35.0, 15.0],
        zoom_start=3,
        tiles="CartoDB dark_matter",
        prefer_canvas=True,
    )

    for pt in points:
        colour = _RISK_HEX.get(pt.get("risk_level", "low"), "#888888")
        popup_html = (
            f"<div style='font-family:monospace;min-width:220px'>"
            f"<b style='color:{colour}'>{pt.get('domain','')}</b><br/>"
            f"IP: <code>{pt.get('ip','?')}</code><br/>"
            f"📍 {pt.get('city','?')}, {pt.get('country','?')}<br/>"
            f"🏢 {pt.get('hosting_provider','?')} ({pt.get('asn','')})<br/>"
            f"🎯 Campagne: <b>{pt.get('campaign','?')}</b><br/>"
            f"⚠️ Score: <b style='color:{colour}'>{pt.get('risk_score',0)}/100</b>"
            f"</div>"
        )
        folium.CircleMarker(
            location=[pt.get("lat", 0), pt.get("lon", 0)],
            radius=max(6, int(pt.get("risk_score", 0)) // 12),
            color=colour,
            fill=True,
            fill_color=colour,
            fill_opacity=0.75,
            popup=folium.Popup(popup_html, max_width=280),
            tooltip=f"{pt.get('domain','')} [{pt.get('risk_level','').upper()}]",
        ).add_to(m)

    # Algeria marker
    folium.Marker(
        location=[36.7372, 3.0865],
        tooltip="🇩🇿 Algérie — Cible des attaques",
        icon=folium.Icon(color="blue", icon="flag"),
    ).add_to(m)

    return m
