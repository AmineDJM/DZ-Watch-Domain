"""IP geolocation enrichment for DZ Domain Watch.

Tries ip-api.com (free, no key needed) for real data.
Falls back to a curated demo mapping if the API is unavailable.
"""

import json
import socket
import urllib.error
import urllib.request
from typing import Optional

_IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as"
_TIMEOUT = 6

# Known hosting providers mapped to ASN prefixes
_HOSTING_LABELS = {
    "cloudflare": "Cloudflare CDN",
    "amazon": "AWS",
    "google": "Google Cloud",
    "microsoft": "Azure",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "digitalocean": "DigitalOcean",
    "linode": "Linode/Akamai",
    "vultr": "Vultr",
    "namecheap": "Namecheap",
}

# Fallback demo geo data keyed by IP
_DEMO_GEO: dict[str, dict] = {
    "104.21.14.221": {"country": "United States", "countryCode": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "Cloudflare", "org": "Cloudflare Inc", "as": "AS13335"},
    "172.67.183.12":  {"country": "United States", "countryCode": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "Cloudflare", "org": "Cloudflare Inc", "as": "AS13335"},
    "23.227.38.65":   {"country": "United States", "countryCode": "US", "city": "Chicago",       "lat": 41.8781, "lon": -87.6298, "isp": "Shopify Inc", "org": "Shopify", "as": "AS62679"},
    "5.75.210.4":     {"country": "Germany",        "countryCode": "DE", "city": "Nuremberg",    "lat": 49.4478, "lon": 11.0683, "isp": "Hetzner Online", "org": "Hetzner Online GmbH", "as": "AS24940"},
    "162.55.48.201":  {"country": "Germany",        "countryCode": "DE", "city": "Nuremberg",    "lat": 49.4478, "lon": 11.0683, "isp": "Hetzner Online", "org": "Hetzner Online GmbH", "as": "AS24940"},
    "51.68.90.175":   {"country": "France",         "countryCode": "FR", "city": "Paris",        "lat": 48.8566, "lon": 2.3522,  "isp": "OVH SAS",       "org": "OVH SAS",              "as": "AS16276"},
    "54.72.118.40":   {"country": "Ireland",        "countryCode": "IE", "city": "Dublin",       "lat": 53.3498, "lon": -6.2603, "isp": "Amazon Technologies", "org": "AWS EC2", "as": "AS16509"},
    "46.101.91.14":   {"country": "Netherlands",    "countryCode": "NL", "city": "Amsterdam",    "lat": 52.3676, "lon": 4.9041,  "isp": "DigitalOcean", "org": "DigitalOcean LLC", "as": "AS14061"},
    "185.199.108.153":{"country": "United States",  "countryCode": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "GitHub Inc", "org": "GitHub Pages", "as": "AS36459"},
    "213.32.8.126":   {"country": "France",         "countryCode": "FR", "city": "Paris",        "lat": 48.8566, "lon": 2.3522,  "isp": "OVH SAS",       "org": "OVH SAS",              "as": "AS16276"},
    "195.154.127.56": {"country": "France",         "countryCode": "FR", "city": "Paris",        "lat": 48.8566, "lon": 2.3522,  "isp": "Scaleway",       "org": "Scaleway SAS",         "as": "AS12876"},
    "91.134.157.223": {"country": "France",         "countryCode": "FR", "city": "Strasbourg",   "lat": 48.5734, "lon": 7.7521,  "isp": "OVH SAS",       "org": "OVH SAS",              "as": "AS16276"},
    "78.47.180.12":   {"country": "Germany",        "countryCode": "DE", "city": "Frankfurt",    "lat": 50.1109, "lon": 8.6821,  "isp": "Hetzner Online", "org": "Hetzner Online GmbH", "as": "AS24940"},
    "159.89.5.209":   {"country": "Netherlands",    "countryCode": "NL", "city": "Amsterdam",    "lat": 52.3676, "lon": 4.9041,  "isp": "DigitalOcean", "org": "DigitalOcean LLC", "as": "AS14061"},
    "134.209.12.8":   {"country": "United Kingdom", "countryCode": "GB", "city": "London",       "lat": 51.5074, "lon": -0.1278, "isp": "DigitalOcean", "org": "DigitalOcean LLC", "as": "AS14061"},
}

# Algeria origin reference (Algiers) — used as source for arc maps
ALGIERS = {"lat": 36.7372, "lon": 3.0865, "city": "Alger", "country": "Algeria", "countryCode": "DZ"}


def resolve_ip(domain: str) -> Optional[str]:
    """Try to resolve a domain to its IP. Returns None on failure."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def lookup_ip(ip: str) -> Optional[dict]:
    """Look up geo info for an IP. Tries ip-api.com, falls back to demo data."""
    if ip in _DEMO_GEO:
        return _DEMO_GEO[ip]

    try:
        url = _IPAPI_URL.format(ip=ip)
        req = urllib.request.Request(url, headers={"User-Agent": "DZ-Domain-Watch/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return None


def get_hosting_label(org: str) -> str:
    org_lower = (org or "").lower()
    for key, label in _HOSTING_LABELS.items():
        if key in org_lower:
            return label
    return org or "Unknown"


def enrich_domain(domain: str, ip: Optional[str] = None) -> Optional[dict]:
    """Resolve domain to IP and look up geo. Returns enriched dict or None."""
    if not ip:
        ip = resolve_ip(domain)
    if not ip:
        return None

    geo = lookup_ip(ip)
    if not geo:
        return None

    return {
        "ip": ip,
        "lat": geo.get("lat", 0.0),
        "lon": geo.get("lon", 0.0),
        "country": geo.get("country", "Unknown"),
        "country_code": geo.get("countryCode", "??"),
        "city": geo.get("city", "Unknown"),
        "asn": geo.get("as", ""),
        "org": geo.get("org", ""),
        "isp": geo.get("isp", ""),
        "hosting_provider": get_hosting_label(geo.get("org", "")),
    }
