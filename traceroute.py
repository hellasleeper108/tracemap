"""
traceroute.py — Run system traceroute, parse hops, geolocate each, cache in DB.
"""

import re
import subprocess
import threading
import time
import db
import geo

CACHE_TTL = 3600  # reuse results for 1 hour

_lock    = threading.Lock()
_running: set[str] = set()


# ── Parsing ────────────────────────────────────────────────────────────────────

def _parse_output(text: str) -> list[dict]:
    hops = []
    for line in text.splitlines()[1:]:  # skip "traceroute to …" header
        # Match: "  1  1.2.3.4  1.234 ms  ..." or "  2  * * *"
        m = re.match(r'^\s*(\d+)\s+([\d.]+|\*)', line)
        if not m:
            continue
        hop_num = int(m.group(1))
        hop_ip  = m.group(2)
        if hop_ip == '*':
            hops.append({"hop": hop_num, "ip": None, "rtt_ms": None})
            continue
        rtt = None
        rtt_m = re.search(r'([\d.]+)\s*ms', line)
        if rtt_m:
            rtt = float(rtt_m.group(1))
        hops.append({"hop": hop_num, "ip": hop_ip, "rtt_ms": rtt})
    return hops


# ── Background worker ──────────────────────────────────────────────────────────

def _trace_and_store(ip: str):
    try:
        result = subprocess.run(
            ["traceroute", "-n", "-m", "20", "-w", "2", ip],
            capture_output=True, text=True, timeout=90
        )
        hops = _parse_output(result.stdout)
    except subprocess.TimeoutExpired:
        hops = []
    except Exception as e:
        print(f"[traceroute] error tracing {ip}: {e}")
        hops = []

    # Geolocate hop IPs
    hop_ips = [h["ip"] for h in hops if h.get("ip")]
    if hop_ips:
        geo_data = geo.geolocate(hop_ips)
        for h in hops:
            if h.get("ip") and h["ip"] in geo_data:
                g = geo_data[h["ip"]]
                h.update({
                    "lat":     g.get("lat"),
                    "lon":     g.get("lon"),
                    "city":    g.get("city"),
                    "country": g.get("country"),
                })

    db.store_traceroute(ip, hops)
    print(f"[traceroute] {ip} — {len(hops)} hops stored")

    with _lock:
        _running.discard(ip)


# ── Public API ─────────────────────────────────────────────────────────────────

def start(ip: str) -> str:
    """Kick off a trace if not already cached or running. Returns status string."""
    cached = db.get_traceroute(ip)
    if cached and (time.time() - cached["ran_at"]) < CACHE_TTL:
        return "cached"

    with _lock:
        if ip in _running:
            return "already_running"
        _running.add(ip)

    threading.Thread(target=_trace_and_store, args=(ip,), daemon=True).start()
    return "running"


def get_result(ip: str) -> dict:
    """Return cached result, running status, or not_found."""
    with _lock:
        if ip in _running:
            return {"status": "running"}

    cached = db.get_traceroute(ip)
    if cached:
        return cached
    return {"status": "not_found"}
