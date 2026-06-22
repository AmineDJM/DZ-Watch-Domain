"""Inject realistic geo demo data for the Geo Intelligence War Room.

4 campaigns targeting Algerian users:
  1. Air Algérie Refund Scam    — Cloudflare/Hetzner hosted
  2. BaridiMob Phishing         — OVH/DigitalOcean hosted
  3. AADL Inscription Fraud     — AWS/Hetzner hosted
  4. Sonatrach Careers Fake     — Cloudflare hosted

Usage: python scripts/run_geo_demo_data.py
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dz_domain_watch.geo_db import (
    init_geo_db,
    insert_geo_arc,
    insert_geo_point,
    upsert_geo_cluster,
)
from dz_domain_watch.geo_enrich import ALGIERS

NOW = datetime.now(tz=timezone.utc)


def ts(delta_hours: int = 0) -> str:
    return (NOW - timedelta(hours=delta_hours)).isoformat()


CAMPAIGNS = [
    # ─── Campaign 1 : Air Algérie Refund Scam ──────────────────────────────
    {
        "campaign": "Air Algérie Refund Scam",
        "risk_level": "critical",
        "points": [
            {
                "domain": "airalgerie-refund-support.com",
                "registered_domain": "airalgerie-refund-support.com",
                "ip": "104.21.14.221",
                "lat": 37.7749, "lon": -122.4194,
                "country": "United States", "country_code": "US",
                "city": "San Francisco",
                "asn": "AS13335", "org": "Cloudflare Inc", "isp": "Cloudflare",
                "hosting_provider": "Cloudflare CDN",
                "risk_score": 95, "risk_level": "critical",
                "seen_utc": ts(2),
            },
            {
                "domain": "airalgerie-ticket-remboursement.xyz",
                "registered_domain": "airalgerie-ticket-remboursement.xyz",
                "ip": "172.67.183.12",
                "lat": 37.7749, "lon": -122.4194,
                "country": "United States", "country_code": "US",
                "city": "San Francisco",
                "asn": "AS13335", "org": "Cloudflare Inc", "isp": "Cloudflare",
                "hosting_provider": "Cloudflare CDN",
                "risk_score": 100, "risk_level": "critical",
                "seen_utc": ts(3),
            },
            {
                "domain": "airalgerie-login-secure.top",
                "registered_domain": "airalgerie-login-secure.top",
                "ip": "5.75.210.4",
                "lat": 49.4478, "lon": 11.0683,
                "country": "Germany", "country_code": "DE",
                "city": "Nuremberg",
                "asn": "AS24940", "org": "Hetzner Online GmbH", "isp": "Hetzner Online",
                "hosting_provider": "Hetzner",
                "risk_score": 90, "risk_level": "critical",
                "seen_utc": ts(5),
            },
            {
                "domain": "airalgerie-customer-verify.net",
                "registered_domain": "airalgerie-customer-verify.net",
                "ip": "162.55.48.201",
                "lat": 49.4478, "lon": 11.0683,
                "country": "Germany", "country_code": "DE",
                "city": "Nuremberg",
                "asn": "AS24940", "org": "Hetzner Online GmbH", "isp": "Hetzner Online",
                "hosting_provider": "Hetzner",
                "risk_score": 85, "risk_level": "critical",
                "seen_utc": ts(6),
            },
            {
                "domain": "airalgerie-dz-booking.online",
                "registered_domain": "airalgerie-dz-booking.online",
                "ip": "46.101.91.14",
                "lat": 52.3676, "lon": 4.9041,
                "country": "Netherlands", "country_code": "NL",
                "city": "Amsterdam",
                "asn": "AS14061", "org": "DigitalOcean LLC", "isp": "DigitalOcean",
                "hosting_provider": "DigitalOcean",
                "risk_score": 80, "risk_level": "critical",
                "seen_utc": ts(8),
            },
        ],
    },
    # ─── Campaign 2 : BaridiMob Phishing ────────────────────────────────────
    {
        "campaign": "BaridiMob Phishing",
        "risk_level": "critical",
        "points": [
            {
                "domain": "baridimob-verification.net",
                "registered_domain": "baridimob-verification.net",
                "ip": "51.68.90.175",
                "lat": 48.8566, "lon": 2.3522,
                "country": "France", "country_code": "FR",
                "city": "Paris",
                "asn": "AS16276", "org": "OVH SAS", "isp": "OVH SAS",
                "hosting_provider": "OVH",
                "risk_score": 95, "risk_level": "critical",
                "seen_utc": ts(1),
            },
            {
                "domain": "baridimob-dz-login.com",
                "registered_domain": "baridimob-dz-login.com",
                "ip": "213.32.8.126",
                "lat": 48.8566, "lon": 2.3522,
                "country": "France", "country_code": "FR",
                "city": "Paris",
                "asn": "AS16276", "org": "OVH SAS", "isp": "OVH SAS",
                "hosting_provider": "OVH",
                "risk_score": 100, "risk_level": "critical",
                "seen_utc": ts(4),
            },
            {
                "domain": "edahabia-payment-confirm.top",
                "registered_domain": "edahabia-payment-confirm.top",
                "ip": "195.154.127.56",
                "lat": 48.8566, "lon": 2.3522,
                "country": "France", "country_code": "FR",
                "city": "Paris",
                "asn": "AS12876", "org": "Scaleway SAS", "isp": "Scaleway",
                "hosting_provider": "Scaleway",
                "risk_score": 95, "risk_level": "critical",
                "seen_utc": ts(7),
            },
            {
                "domain": "baridimob-secure-update.xyz",
                "registered_domain": "baridimob-secure-update.xyz",
                "ip": "159.89.5.209",
                "lat": 52.3676, "lon": 4.9041,
                "country": "Netherlands", "country_code": "NL",
                "city": "Amsterdam",
                "asn": "AS14061", "org": "DigitalOcean LLC", "isp": "DigitalOcean",
                "hosting_provider": "DigitalOcean",
                "risk_score": 90, "risk_level": "critical",
                "seen_utc": ts(10),
            },
        ],
    },
    # ─── Campaign 3 : AADL Inscription Fraud ────────────────────────────────
    {
        "campaign": "AADL Inscription Fraud",
        "risk_level": "high",
        "points": [
            {
                "domain": "aadl-inscription-2026.com",
                "registered_domain": "aadl-inscription-2026.com",
                "ip": "54.72.118.40",
                "lat": 53.3498, "lon": -6.2603,
                "country": "Ireland", "country_code": "IE",
                "city": "Dublin",
                "asn": "AS16509", "org": "Amazon Technologies", "isp": "Amazon",
                "hosting_provider": "AWS",
                "risk_score": 75, "risk_level": "high",
                "seen_utc": ts(12),
            },
            {
                "domain": "aadl3-dossier-2026.net",
                "registered_domain": "aadl3-dossier-2026.net",
                "ip": "78.47.180.12",
                "lat": 50.1109, "lon": 8.6821,
                "country": "Germany", "country_code": "DE",
                "city": "Frankfurt",
                "asn": "AS24940", "org": "Hetzner Online GmbH", "isp": "Hetzner Online",
                "hosting_provider": "Hetzner",
                "risk_score": 70, "risk_level": "high",
                "seen_utc": ts(14),
            },
            {
                "domain": "algerie-logement-inscription.org",
                "registered_domain": "algerie-logement-inscription.org",
                "ip": "91.134.157.223",
                "lat": 48.5734, "lon": 7.7521,
                "country": "France", "country_code": "FR",
                "city": "Strasbourg",
                "asn": "AS16276", "org": "OVH SAS", "isp": "OVH SAS",
                "hosting_provider": "OVH",
                "risk_score": 65, "risk_level": "high",
                "seen_utc": ts(18),
            },
        ],
    },
    # ─── Campaign 4 : Sonatrach Careers Fake ────────────────────────────────
    {
        "campaign": "Sonatrach Careers Fake",
        "risk_level": "high",
        "points": [
            {
                "domain": "sonatrach-careers.org",
                "registered_domain": "sonatrach-careers.org",
                "ip": "104.21.14.221",
                "lat": 37.7749, "lon": -122.4194,
                "country": "United States", "country_code": "US",
                "city": "San Francisco",
                "asn": "AS13335", "org": "Cloudflare Inc", "isp": "Cloudflare",
                "hosting_provider": "Cloudflare CDN",
                "risk_score": 75, "risk_level": "high",
                "seen_utc": ts(20),
            },
            {
                "domain": "sonatrach-recrutement-dz.com",
                "registered_domain": "sonatrach-recrutement-dz.com",
                "ip": "134.209.12.8",
                "lat": 51.5074, "lon": -0.1278,
                "country": "United Kingdom", "country_code": "GB",
                "city": "London",
                "asn": "AS14061", "org": "DigitalOcean LLC", "isp": "DigitalOcean",
                "hosting_provider": "DigitalOcean",
                "risk_score": 80, "risk_level": "critical",
                "seen_utc": ts(22),
            },
            {
                "domain": "sonatrach-emploi-algerie.net",
                "registered_domain": "sonatrach-emploi-algerie.net",
                "ip": "5.75.210.4",
                "lat": 49.4478, "lon": 11.0683,
                "country": "Germany", "country_code": "DE",
                "city": "Nuremberg",
                "asn": "AS24940", "org": "Hetzner Online GmbH", "isp": "Hetzner Online",
                "hosting_provider": "Hetzner",
                "risk_score": 70, "risk_level": "high",
                "seen_utc": ts(24),
            },
        ],
    },
]


def main() -> None:
    print("🌍 Injection des données démo Geo Intelligence War Room…")
    init_geo_db()

    total_points = 0
    total_arcs = 0
    total_clusters = 0

    for camp in CAMPAIGNS:
        camp_name = camp["campaign"]
        points = camp["points"]
        domains_in_camp = []

        for pt in points:
            pt.setdefault("campaign", camp_name)
            pt.setdefault("inserted_at_utc", NOW.isoformat())
            if insert_geo_point(pt):
                total_points += 1

            # Arc from Algiers to server location
            arc = {
                "domain": pt["domain"],
                "src_lat": ALGIERS["lat"],
                "src_lon": ALGIERS["lon"],
                "src_city": ALGIERS["city"],
                "dst_lat": pt["lat"],
                "dst_lon": pt["lon"],
                "dst_city": pt["city"],
                "campaign": camp_name,
                "risk_score": pt["risk_score"],
                "risk_level": pt["risk_level"],
                "seen_utc": pt["seen_utc"],
            }
            if insert_geo_arc(arc):
                total_arcs += 1

            domains_in_camp.append(pt["domain"])

        # Cluster summary
        scores = [p["risk_score"] for p in points]
        countries = list({p["country"] for p in points})
        lats = [p["lat"] for p in points]
        lons = [p["lon"] for p in points]
        center_lat = sum(lats) / len(lats)
        center_lon = sum(lons) / len(lons)
        max_score = max(scores)

        cluster = {
            "campaign": camp_name,
            "count": len(points),
            "countries": json.dumps(countries, ensure_ascii=False),
            "risk_max": max_score,
            "risk_level": camp["risk_level"],
            "center_lat": center_lat,
            "center_lon": center_lon,
            "domains": json.dumps(domains_in_camp, ensure_ascii=False),
            "updated_at": NOW.isoformat(),
        }
        upsert_geo_cluster(cluster)
        total_clusters += 1

        print(f"  ✅ {camp_name} — {len(points)} domaines, score max: {max_score}")

    print(f"\n✅ Injection terminée :")
    print(f"   {total_points} geo_points insérés")
    print(f"   {total_arcs} arcs insérés")
    print(f"   {total_clusters} clusters mis à jour")
    print("\n🚀 Lance le dashboard pour voir la Geo War Room !")


if __name__ == "__main__":
    main()
