"""
reputation.py — Tor exit-node detection and VPN org-name heuristics.

Maintains an in-memory set of Tor exit IPs backed by a DB cache so a
restart does not require an immediate network hit.  Refreshes every
TOR_REFRESH seconds in a background thread started by tracemap.py.
"""

import threading
import time
import urllib.request
import urllib.error
import db

TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_REFRESH  = 6 * 3600   # re-fetch every 6 hours
TOR_SOURCE   = "tor_exit"

_VPN_KEYWORDS = [
    "nordvpn", "expressvpn", "protonvpn", "mullvad", "surfshark",
    "private internet access", "pia vpn", "ipvanish", "cyberghost",
    "tunnelbear", "windscribe", "astrill", "hotspot shield",
    "hide.me", "vyprvpn", "purevpn", "strongvpn", "hidemyass",
]

_lock       = threading.Lock()
_exits: set = set()
_fetched_at = 0.0


def _fetch() -> list[str]:
    """Download plain-text Tor exit list; returns [] on failure."""
    try:
        req = urllib.request.Request(
            TOR_LIST_URL, headers={"User-Agent": "tracemap/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        return [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except Exception as e:
        print(f"[reputation] Tor exit list fetch failed: {e}")
        return []


def _apply(ips: list[str], fetched: float):
    global _fetched_at
    with _lock:
        _exits.clear()
        _exits.update(ips)
        _fetched_at = fetched


def _do_refresh():
    ips = _fetch()
    if ips:
        db.bulk_set_reputation(TOR_SOURCE, ips)
        _apply(ips, time.time())
        print(f"[reputation] Tor exit list: {len(ips)} IPs loaded")


def is_tor(ip: str) -> bool:
    with _lock:
        return ip in _exits


def is_vpn(org: str) -> bool:
    """Heuristic check on the org/ISP string from geo data."""
    if not org:
        return False
    lower = org.lower()
    return any(kw in lower for kw in _VPN_KEYWORDS)


def checker_loop():
    """
    Background loop.  On first run: load from DB cache if fresh, otherwise
    fetch from network.  Then refresh every TOR_REFRESH seconds.
    """
    ts = db.get_reputation_fetched_at(TOR_SOURCE)
    if ts and (time.time() - ts) < TOR_REFRESH:
        ips = db.get_reputation_ips(TOR_SOURCE)
        if ips:
            _apply(ips, ts)
            print(f"[reputation] Tor cache loaded: {len(ips)} IPs "
                  f"({int((time.time()-ts)/60)} min old)")
    else:
        _do_refresh()

    while True:
        time.sleep(3600)
        if time.time() - _fetched_at >= TOR_REFRESH:
            _do_refresh()
