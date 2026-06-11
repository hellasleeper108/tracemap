"""
geo.py — IP geolocation with DB-backed cache.

Supports optional offline lookup via MaxMind GeoLite2 .mmdb files.
Call set_geoip_paths() before first use to enable offline mode.
IPv6 addresses are valid inputs to both the offline readers and ip-api.com.
"""

import json
import logging
import time
import urllib.request
import urllib.error
import db

BATCH_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,org,isp"
HOST_URL  = "http://ip-api.com/json/?fields=status,query,country,city,lat,lon,org"
GEO_TTL   = 7 * 24 * 3600  # re-fetch after 7 days

# Offline MaxMind readers (None when not configured / maxminddb unavailable)
_geoip_db: object = None   # GeoLite2-City reader
_geoip_asn: object = None  # GeoLite2-ASN reader


def set_geoip_paths(city_path: "str | None", asn_path: "str | None") -> None:
    """Configure offline MaxMind GeoLite2 readers.

    Requires the optional ``maxminddb`` package.  If the package is not
    installed a warning is printed and the module falls back to ip-api.com.
    """
    global _geoip_db, _geoip_asn
    if not city_path and not asn_path:
        return
    try:
        import maxminddb  # type: ignore
    except ImportError:
        logging.warning(
            "[geo] maxminddb package not installed — offline GeoIP unavailable. "
            "Install with: pip install maxminddb"
        )
        return
    if city_path:
        try:
            _geoip_db = maxminddb.open_database(city_path)
            logging.info("[geo] Loaded GeoLite2-City from %s", city_path)
        except Exception as exc:
            logging.warning("[geo] Failed to open GeoLite2-City %s: %s", city_path, exc)
    if asn_path:
        try:
            _geoip_asn = maxminddb.open_database(asn_path)
            logging.info("[geo] Loaded GeoLite2-ASN from %s", asn_path)
        except Exception as exc:
            logging.warning("[geo] Failed to open GeoLite2-ASN %s: %s", asn_path, exc)


def is_offline() -> bool:
    """Return True when at least one offline MaxMind reader is loaded."""
    return _geoip_db is not None or _geoip_asn is not None


def _lookup_offline(ip: str) -> "dict | None":
    """Query offline MaxMind readers for a single IP.  Returns None on miss."""
    if not is_offline():
        return None
    try:
        city_rec = _geoip_db.get(ip) if _geoip_db else None
        asn_rec  = _geoip_asn.get(ip) if _geoip_asn else None
    except Exception:
        return None

    # Build a response dict that mirrors the ip-api.com shape used elsewhere.
    result: dict = {"query": ip, "status": "success"}

    if city_rec:
        country      = city_rec.get("country") or {}
        country_iso  = (country.get("iso_code") or "")
        names        = country.get("names") or {}
        country_name = names.get("en") or ""
        city_obj     = city_rec.get("city") or {}
        city_names   = city_obj.get("names") or {}
        city_name    = city_names.get("en") or ""
        location     = city_rec.get("location") or {}
        result["country"]     = country_name
        result["countryCode"] = country_iso
        result["city"]        = city_name
        result["lat"]         = location.get("latitude") or 0
        result["lon"]         = location.get("longitude") or 0

    if asn_rec:
        org = asn_rec.get("autonomous_system_organization") or ""
        result["org"] = org
        result["isp"] = org

    # Only return if we got at least some useful data
    if city_rec or asn_rec:
        return result
    return None


def _fetch_batch(ips: list[str]) -> dict[str, dict]:
    payload = json.dumps([{"query": ip} for ip in ips[:100]]).encode()
    req = urllib.request.Request(
        BATCH_URL, data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read())
        return {r["query"]: r for r in results if r.get("status") == "success"}
    except urllib.error.URLError as e:
        print(f"[geo] batch fetch failed: {e}")
        return {}


def geolocate(ips: list[str]) -> dict[str, dict]:
    """Return geo data for each IP, pulling from DB cache or fetching as needed.

    Lookup order:
      1. DB cache (if fresh)
      2. Offline MaxMind readers (when set_geoip_paths() was called)
      3. ip-api.com (online fallback — also handles IPv6)
    """
    result: dict[str, dict] = {}
    to_fetch: list[str] = []
    now = int(time.time())

    for ip in ips:
        cached = db.get_geo(ip)
        if cached and (now - (cached.get("fetched_at") or 0)) < GEO_TTL:
            result[ip] = cached
        else:
            to_fetch.append(ip)

    if to_fetch:
        # Try offline readers first; fall back to ip-api.com for misses.
        still_needed: list[str] = []
        for ip in to_fetch:
            offline = _lookup_offline(ip)
            if offline:
                db.set_geo(ip, offline)
                result[ip] = offline
            else:
                still_needed.append(ip)

        if still_needed:
            fetched = _fetch_batch(still_needed)
            for ip, data in fetched.items():
                db.set_geo(ip, data)
                result[ip] = data

    return result


def get_host_geo() -> dict:
    try:
        with urllib.request.urlopen(HOST_URL, timeout=8) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {"lat": 0, "lon": 0, "query": "unknown", "city": "Unknown", "country": ""}
