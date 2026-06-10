"""
collector.py — ss polling, connection parsing, and the background updater loop.
Owns the shared in-memory state that the server reads.
"""

import http.client
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

REFRESH_INTERVAL    = 5    # seconds between poll cycles
CONTAINER_CACHE_TTL = 60   # seconds to cache container name lookups

_lock          = threading.Lock()
_connections:  list[dict] = []
_host_geo:     dict       = {}
_last_updated: float      = 0.0

# ── Bandwidth state ────────────────────────────────────────────────────────────
# keyed by (ip, port, local_port) → {bytes_recv, bytes_sent, ts}
_bw_state: dict[tuple, dict] = {}

# ── Container name cache ───────────────────────────────────────────────────────
# keyed by container_id → (name_or_None, fetched_at)
_container_cache: dict[str, tuple[str | None, float]] = {}


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


def _extract_pid(proc_field: str) -> int | None:
    m = re.search(r'pid=(\d+)', proc_field)
    return int(m.group(1)) if m else None


def _is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def _parse_bw_info(info_line: str) -> tuple[int, int]:
    """Extract (bytes_recv, bytes_sent) from ss -i extended info line."""
    m = re.search(r'\bbytes_received:(\d+)', info_line)
    bytes_recv = int(m.group(1)) if m else 0
    # bytes_sent direct (newer ss) or bytes_acked (older ss)
    m2 = re.search(r'\bbytes_sent:(\d+)', info_line)
    m3 = re.search(r'\bbytes_acked:(\d+)', info_line)
    bytes_sent = int(m2.group(1)) if m2 else (int(m3.group(1)) if m3 else 0)
    return bytes_recv, bytes_sent


def _compute_bw(key: tuple, bytes_recv: int, bytes_sent: int,
                now: float) -> tuple[float, float]:
    """Return (recv_bps, send_bps) by diffing against stored state."""
    prev = _bw_state.get(key)
    if prev and now > prev["ts"] and bytes_recv >= prev["bytes_recv"]:
        dt        = now - prev["ts"]
        recv_bps  = (bytes_recv - prev["bytes_recv"]) / dt
        send_bps  = max(0, bytes_sent - prev["bytes_sent"]) / dt
    else:
        recv_bps = send_bps = 0.0
    _bw_state[key] = {"bytes_recv": bytes_recv, "bytes_sent": bytes_sent, "ts": now}
    return recv_bps, send_bps


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


# ── Docker detection ──────────────────────────────────────────────────────────

def _get_container_id(pid: int) -> str | None:
    """Read /proc/<pid>/cgroup to find a Docker container ID (12-char prefix)."""
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            for line in f:
                m = re.search(r'/docker/([0-9a-f]{12,64})', line)
                if m:
                    return m.group(1)[:12]
    except OSError:
        pass
    return None


class _UnixHTTP(http.client.HTTPConnection):
    """HTTP over a Unix domain socket (for Docker socket API)."""
    def __init__(self, path: str):
        super().__init__("localhost")
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(self._path)
        self.sock = s


def _get_container_name(container_id: str) -> str | None:
    """Query Docker socket for the container name; returns None on failure."""
    now = time.time()
    if container_id in _container_cache:
        name, ts = _container_cache[container_id]
        if now - ts < CONTAINER_CACHE_TTL:
            return name

    name: str | None = None
    try:
        conn = _UnixHTTP("/var/run/docker.sock")
        conn.request("GET", f"/containers/{container_id}/json")
        resp = conn.getresponse()
        if resp.status == 200:
            data = json.loads(resp.read())
            raw  = data.get("Name", "")
            name = raw.lstrip("/") or None
        conn.close()
    except Exception:
        pass

    _container_cache[container_id] = (name, now)
    return name


def _resolve_container(pid: int | None) -> tuple[str, str]:
    """Return (container_id, container_name) for a process; both empty if not Docker."""
    if pid is None:
        return "", ""
    cid = _get_container_id(pid)
    if not cid:
        return "", ""
    cname = _get_container_name(cid) or ""
    return cid, cname


# ── Connection polling ─────────────────────────────────────────────────────────

def get_connections() -> list[dict]:
    """Return deduplicated list of active public TCP connections with bandwidth."""
    try:
        result = subprocess.run(
            ["ss", "-tnpi", "state", "established"],
            capture_output=True, text=True, timeout=5
        )
    except Exception:
        return []

    now   = time.time()
    lines = result.stdout.splitlines()

    # Group lines: each non-whitespace line starts a new connection entry;
    # subsequent indented lines are extended info for that connection.
    groups: list[list[str]] = []
    for line in lines[1:]:  # skip header
        if not line:
            continue
        if line[0].isspace():
            if groups:
                groups[-1].append(line)
        else:
            groups.append([line])

    conns = []
    for group in groups:
        main_line  = group[0]
        info_lines = group[1:]

        parts = main_line.split()
        if len(parts) < 4:
            continue

        local_col  = parts[2]
        peer_col   = parts[3]
        proc_field = " ".join(parts[4:]) if len(parts) > 4 else ""

        ip, port = _parse_peer(peer_col)
        if not ip or not _is_public(ip):
            continue

        _, local_port = _parse_peer(local_col)

        # Bandwidth from extended info
        bytes_recv = bytes_sent = 0
        for info in info_lines:
            r, s = _parse_bw_info(info)
            if r or s:
                bytes_recv, bytes_sent = r, s
                break

        key = (ip, port or "", local_port or "")
        recv_bps, send_bps = _compute_bw(key, bytes_recv, bytes_sent, now)

        pid = _extract_pid(proc_field)
        conns.append({
            "ip":         ip,
            "port":       port,
            "local_port": local_port or "",
            "process":    _extract_process(proc_field),
            "pid":        pid,
            "bytes_recv": bytes_recv,
            "bytes_sent": bytes_sent,
            "recv_bps":   recv_bps,
            "send_bps":   send_bps,
        })

    # Deduplicate by (ip, port), keeping first occurrence
    seen:   set[tuple] = set()
    unique: list[dict] = []
    for c in conns:
        key2 = (c["ip"], c["port"])
        if key2 not in seen:
            seen.add(key2)
            unique.append(c)

    # Prune stale bandwidth state entries
    active_keys = {(c["ip"], c["port"] or "", c["local_port"]) for c in unique}
    for k in list(_bw_state):
        if k not in active_keys:
            del _bw_state[k]

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

        ips      = list({c["ip"] for c in conns})
        geo_data = geo.geolocate(ips)
        dns_data = resolve_hostnames(ips)

        enriched = []
        for c in conns:
            g = geo_data.get(c["ip"])
            if g:
                entry = {**c, **g}
                entry["hostname"]  = dns_data.get(c["ip"], "")
                entry["is_tor"]    = reputation.is_tor(c["ip"])
                entry["is_vpn"]    = reputation.is_vpn(g.get("org", ""))
                entry["is_blocked"] = db.is_blocked_ip(c["ip"])

                # Docker container info
                cid, cname = _resolve_container(c.get("pid"))
                entry["container_id"]   = cid
                entry["container"]      = cname

                t = db.get_threat(c["ip"])
                if t:
                    entry["abuse_score"]    = t["abuse_score"]
                    entry["threat_reports"] = t["reports"]

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
