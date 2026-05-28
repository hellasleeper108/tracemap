"""
geo.py — IP geolocation with DB-backed cache.
"""

import json
import time
import urllib.request
import urllib.error
import db

BATCH_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,org,isp"
HOST_URL  = "http://ip-api.com/json/?fields=status,query,country,city,lat,lon,org"
GEO_TTL   = 7 * 24 * 3600  # re-fetch after 7 days


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
    """Return geo data for each IP, pulling from DB cache or fetching as needed."""
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
        fetched = _fetch_batch(to_fetch)
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
