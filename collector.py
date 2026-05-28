"""
collector.py — ss polling, connection parsing, and the background updater loop.
Owns the shared in-memory state that the server reads.
"""

import re
import subprocess
import ipaddress
import threading
import time
import db
import geo
import threat

REFRESH_INTERVAL = 5  # seconds

_lock          = threading.Lock()
_connections:  list[dict] = []
_host_geo:     dict       = {}
_last_updated: float      = 0.0


# ── Parsing helpers ────────────────────────────────────────────────────────────

def _parse_peer(addr_port: str) -> tuple[str | None, str | None]:
    """Split 'ip:port' from ss output, handling IPv4 and bracketed IPv6."""
    if addr_port.startswith("["):
        m = re.match(r"\[(.+)\]:(\d+)", addr_port)
        if m:
            return m.group(1), m.group(2)
    else:
        idx = addr_port.rfind(":")
        if idx != -1:
            return addr_port[:idx], addr_port[idx + 1:]
    return None, None


def _extract_process(proc_field: str) -> str:
    m = re.search(r'users:\(\("([^"]+)"', proc_field)
    return m.group(1) if m else ""


def _is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


# ── Connection polling ─────────────────────────────────────────────────────────

def get_connections() -> list[dict]:
    """Return deduplicated list of active public TCP connections."""
    try:
        result = subprocess.run(
            ["ss", "-tnp", "state", "established"],
            capture_output=True, text=True, timeout=5
        )
    except Exception:
        return []

    conns = []
    for line in result.stdout.splitlines()[1:]:  # skip header row
        parts = line.split()
        if len(parts) < 4:
            continue

        local_col  = parts[2]
        peer_col   = parts[3]
        proc_field = " ".join(parts[4:]) if len(parts) > 4 else ""

        ip, port = _parse_peer(peer_col)
        if not ip or not _is_public(ip):
            continue

        _, local_port = _parse_peer(local_col)
        conns.append({
            "ip":         ip,
            "port":       port,
            "local_port": local_port or "",
            "process":    _extract_process(proc_field),
        })

    # Deduplicate by (ip, port), keeping first occurrence
    seen: set[tuple] = set()
    unique = []
    for c in conns:
        key = (c["ip"], c["port"])
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


# ── Shared state access ────────────────────────────────────────────────────────

def get_state() -> dict:
    """Thread-safe snapshot of current state for the server to return."""
    with _lock:
        return {
            "host":           dict(_host_geo),
            "connections":    list(_connections),
            "last_updated":   _last_updated,
            "threat_enabled": threat.is_enabled(),
        }


# ── Background loop ────────────────────────────────────────────────────────────

def updater_loop():
    global _connections, _host_geo, _last_updated

    host = geo.get_host_geo()
    with _lock:
        _host_geo = host

    while True:
        conns = get_connections()

        if conns:
            db.log_connections(conns)

        ips = list({c["ip"] for c in conns})
        geo_data = geo.geolocate(ips)

        enriched = []
        for c in conns:
            g = geo_data.get(c["ip"])
            if g:
                entry = {**c, **g}
                t = db.get_threat(c["ip"])
                if t:
                    entry["abuse_score"] = t["abuse_score"]
                    entry["threat_reports"] = t["reports"]
                enriched.append(entry)

        with _lock:
            _connections  = enriched
            _last_updated = time.time()

        time.sleep(REFRESH_INTERVAL)
