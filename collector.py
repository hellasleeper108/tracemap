"""
collector.py — ss polling, connection parsing, and the background updater loop.
Owns the shared in-memory state that the server reads.
"""

import json
import re
import socket
import subprocess
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import db
import geo
import threat
import reputation
import alerts

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


# ── DNS resolution ────────────────────────────────────────────────────────────

def _resolve_hostname(ip: str) -> tuple[str, str]:
    """Resolve FQDN for an IP; return empty string when unresolvable."""
    try:
        name = socket.getfqdn(ip)
        return ip, ("" if name == ip else name)
    except Exception:
        return ip, ""


def resolve_hostnames(ips: list[str]) -> dict[str, str]:
    """Return {ip: hostname} for given IPs using DB cache (24h TTL)."""
    result: dict[str, str] = {}
    to_resolve: list[str] = []

    for ip in ips:
        cached = db.get_hostname(ip)
        if cached is not None:
            result[ip] = cached
        else:
            to_resolve.append(ip)

    if to_resolve:
        with ThreadPoolExecutor(max_workers=min(10, len(to_resolve))) as pool:
            for ip, hostname in pool.map(_resolve_hostname, to_resolve):
                result[ip] = hostname
                db.set_hostname(ip, hostname)

    return result


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
        dns_data = resolve_hostnames(ips)

        enriched = []
        for c in conns:
            g = geo_data.get(c["ip"])
            if g:
                entry = {**c, **g}
                entry["hostname"] = dns_data.get(c["ip"], "")
                entry["is_tor"]   = reputation.is_tor(c["ip"])
                entry["is_vpn"]   = reputation.is_vpn(g.get("org", ""))
                t = db.get_threat(c["ip"])
                if t:
                    entry["abuse_score"]    = t["abuse_score"]
                    entry["threat_reports"] = t["reports"]
                # Merge multi-source threat scores
                sources = db.get_threat_sources(c["ip"])
                if sources:
                    entry["threat_sources"] = [
                        {"source": s["source"], "score": s["score"],
                         "raw": json.loads(s["raw"])}
                        for s in sources
                    ]
                    max_src = max(s["score"] for s in sources)
                    if max_src > (entry.get("abuse_score") or 0):
                        entry["abuse_score"] = max_src
                enriched.append(entry)

        alerts.evaluate(enriched)

        with _lock:
            _connections  = enriched
            _last_updated = time.time()

        time.sleep(REFRESH_INTERVAL)
