"""
geo.py — IP geolocation with DB-backed cache.
"""

import ipaddress as _ipaddress
import json
import struct as _struct
import time
import urllib.request
import urllib.error
import db

BATCH_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,org,isp"
HOST_URL  = "http://ip-api.com/json/?fields=status,query,country,city,lat,lon,org"
GEO_TTL   = 7 * 24 * 3600  # re-fetch after 7 days

_geoip_db_path: str | None = None   # set by configure_geoip_db()
_geoip_asn_path: str | None = None  # set by configure_geoip_db()


def flag(cc: str) -> str:
    """Convert ISO-3166-1 alpha-2 country code to flag emoji."""
    if not cc or len(cc) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


def configure_geoip_db(city_path: str | None, asn_path: str | None = None):
    global _geoip_db_path, _geoip_asn_path
    _geoip_db_path  = city_path
    _geoip_asn_path = asn_path
    if city_path:
        print(f"[geo] Using local GeoIP DB: {city_path}")
    if asn_path:
        print(f"[geo] Using local ASN DB: {asn_path}")


def _mmdb_lookup(db_path: str, ip_str: str) -> dict | None:
    """Minimal stdlib MMDB reader. Returns the record dict or None."""
    try:
        with open(db_path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    # Locate metadata separator \xab\xcd\xefMaxMind.com
    sep = b"\xab\xcd\xefMaxMind.com"
    meta_start = raw.rfind(sep)
    if meta_start == -1:
        return None
    meta_start += len(sep)
    meta = _mmdb_decode(raw, meta_start)[0]
    node_count      = meta.get("node_count", 0)
    record_size     = meta.get("record_size", 28)
    ip_version      = meta.get("ip_version", 6)
    node_byte_size  = (record_size * 2) // 8
    search_tree_end = node_count * node_byte_size
    data_start      = search_tree_end + 16  # 16-byte separator

    # Convert IP to bit string
    try:
        addr = _ipaddress.ip_address(ip_str)
        if ip_version == 6 and addr.version == 4:
            addr = _ipaddress.ip_address("::ffff:" + ip_str)
        bits = format(int(addr), f"0{addr.max_prefixlen}b")
    except ValueError:
        return None

    # Walk search tree
    node = 0
    for bit in bits:
        if node >= node_count:
            break
        offset = node * node_byte_size
        if record_size == 28:
            if bit == "0":
                b = raw[offset:offset + 4]
                node = ((b[3] & 0xF0) << 20) | (b[0] << 16) | (b[1] << 8) | b[2]
            else:
                b = raw[offset:offset + 4]
                node = ((b[3] & 0x0F) << 24) | (raw[offset + 4] << 16) | (raw[offset + 5] << 8) | raw[offset + 6]
        elif record_size == 24:
            if bit == "0":
                b = raw[offset:offset + 3]
                node = (b[0] << 16) | (b[1] << 8) | b[2]
            else:
                b = raw[offset + 3:offset + 6]
                node = (b[0] << 16) | (b[1] << 8) | b[2]
        elif record_size == 32:
            if bit == "0":
                node = _struct.unpack(">I", raw[offset:offset + 4])[0]
            else:
                node = _struct.unpack(">I", raw[offset + 4:offset + 8])[0]
        else:
            return None

    if node == node_count:  # empty record
        return None
    if node <= node_count:
        return None

    # Decode data record
    record_offset = data_start + (node - node_count - 16)
    if record_offset < 0 or record_offset >= len(raw):
        return None
    result, _ = _mmdb_decode(raw, record_offset)
    return result if isinstance(result, dict) else None


def _mmdb_decode(data: bytes, offset: int):
    """Decode a single MMDB data record. Returns (value, new_offset)."""
    if offset >= len(data):
        return None, offset
    ctrl = data[offset]; offset += 1
    dtype = (ctrl >> 5) & 0x7
    size  = ctrl & 0x1F
    if dtype == 0:  # extended type
        if offset >= len(data):
            return None, offset
        dtype = data[offset] + 7; offset += 1
    if size == 29:
        size = data[offset] + 29; offset += 1
    elif size == 30:
        size = _struct.unpack(">H", data[offset:offset + 2])[0] + 285; offset += 2
    elif size == 31:
        size = ((_struct.unpack(">I", b'\x00' + data[offset:offset + 3])[0]) + 65821); offset += 3

    if dtype == 1:    # pointer
        ptr_size = (size >> 3) & 0x3
        v = size & 0x7
        if ptr_size == 0:
            ptr = (v << 8) | data[offset]; offset += 1
        elif ptr_size == 1:
            ptr = (v << 16) | (data[offset] << 8) | data[offset + 1] + 2048; offset += 2
        elif ptr_size == 2:
            ptr = (v << 24) | (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2] + 526336; offset += 3
        else:
            ptr = _struct.unpack(">I", data[offset:offset + 4])[0]; offset += 4
        val, _ = _mmdb_decode(data, ptr)
        return val, offset
    elif dtype == 2:  # utf-8 string
        return data[offset:offset + size].decode("utf-8", errors="replace"), offset + size
    elif dtype == 3:  # double
        return _struct.unpack(">d", data[offset:offset + 8])[0], offset + 8
    elif dtype == 4:  # bytes
        return data[offset:offset + size], offset + size
    elif dtype == 5:  # uint16
        return int.from_bytes(data[offset:offset + size], "big"), offset + size
    elif dtype == 6:  # uint32
        return int.from_bytes(data[offset:offset + size], "big"), offset + size
    elif dtype == 7:  # map
        result = {}
        for _ in range(size):
            k, offset = _mmdb_decode(data, offset)
            v, offset = _mmdb_decode(data, offset)
            if k is not None:
                result[str(k)] = v
        return result, offset
    elif dtype == 8:  # int32
        return _struct.unpack(">i", data[offset:offset + size])[0], offset + size
    elif dtype == 9:  # uint64
        return int.from_bytes(data[offset:offset + size], "big"), offset + size
    elif dtype == 10: # uint128
        return int.from_bytes(data[offset:offset + size], "big"), offset + size
    elif dtype == 11: # array
        result = []
        for _ in range(size):
            v, offset = _mmdb_decode(data, offset)
            result.append(v)
        return result, offset
    elif dtype == 14: # bool
        return size != 0, offset
    elif dtype == 15: # float
        return _struct.unpack(">f", data[offset:offset + 4])[0], offset + 4
    return None, offset + size


def _mmdb_to_geo(rec: dict) -> dict | None:
    """Convert a GeoLite2-City mmdb record to our geo dict format."""
    if not rec:
        return None
    loc  = rec.get("location", {}) or {}
    city = rec.get("city", {}) or {}
    cc_rec = rec.get("country", {}) or rec.get("registered_country", {}) or {}
    names  = city.get("names", {}) or {}
    cc_names = cc_rec.get("names", {}) or {}
    return {
        "country":     cc_names.get("en", ""),
        "countryCode": cc_rec.get("iso_code", ""),
        "city":        names.get("en", ""),
        "lat":         loc.get("latitude"),
        "lon":         loc.get("longitude"),
        "org":         "",
        "isp":         "",
    }


def _mmdb_to_asn(rec: dict) -> dict | None:
    """Convert a GeoLite2-ASN mmdb record to {asn, as_name}."""
    if not rec:
        return None
    return {
        "asn":     rec.get("autonomous_system_number"),
        "as_name": rec.get("autonomous_system_organization", ""),
    }


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
        if _geoip_db_path:
            for ip in to_fetch:
                rec = _mmdb_lookup(_geoip_db_path, ip)
                geo = _mmdb_to_geo(rec) if rec else None
                if geo:
                    if _geoip_asn_path:
                        asn_rec = _mmdb_lookup(_geoip_asn_path, ip)
                        asn     = _mmdb_to_asn(asn_rec) if asn_rec else {}
                        geo["org"] = asn.get("as_name", "")
                        geo["asn"] = asn.get("asn")
                        geo["isp"] = ""
                    db.set_geo(ip, geo)
                    result[ip] = geo
        else:
            fetched = _fetch_batch(to_fetch)
            for ip, data in fetched.items():
                db.set_geo(ip, data)
                result[ip] = data

    return result


def get_geo_status() -> dict:
    return {
        "source":       "local" if _geoip_db_path else "ip-api.com",
        "city_db":      _geoip_db_path,
        "asn_db":       _geoip_asn_path,
    }


def get_host_geo() -> dict:
    try:
        with urllib.request.urlopen(HOST_URL, timeout=8) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {"lat": 0, "lon": 0, "query": "unknown", "city": "Unknown", "country": ""}
