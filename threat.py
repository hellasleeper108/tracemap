"""
threat.py — AbuseIPDB threat intelligence checker.

Set ABUSEIPDB_KEY in your environment to enable.
Get a free key at https://www.abuseipdb.com/register
"""

import json
import os
import time
import urllib.request
import urllib.error
import db

CHECK_URL  = "https://api.abuseipdb.com/api/v2/check"
THREAT_TTL = 24 * 3600   # re-check after 24 hours
BATCH_SIZE = 5            # IPs to check per cycle
CYCLE_WAIT = 15           # seconds between checker cycles
IP_WAIT    = 2            # seconds between individual API calls


def _api_key() -> str | None:
    return os.environ.get("ABUSEIPDB_KEY")


def is_enabled() -> bool:
    return bool(_api_key())


def _check_ip(ip: str, api_key: str) -> dict | None:
    url = f"{CHECK_URL}?ipAddress={ip}&maxAgeInDays=90&verbose"
    req = urllib.request.Request(url, headers={
        "Key":    api_key,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            d = body.get("data", {})
            return {
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "reports":     d.get("totalReports", 0),
            }
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print("[threat] Rate limited by AbuseIPDB — backing off 60s")
            time.sleep(60)
        else:
            print(f"[threat] HTTP {e.code} checking {ip}")
    except urllib.error.URLError as e:
        print(f"[threat] Network error checking {ip}: {e}")
    return None


def checker_loop():
    """Background loop that fills threat_cache for known IPs."""
    key = _api_key()
    if not key:
        print("[threat] ABUSEIPDB_KEY not set — threat intelligence disabled.")
        return

    print("[threat] Threat intelligence enabled.")
    while True:
        ips = db.get_ips_needing_threat_check(THREAT_TTL, limit=BATCH_SIZE)
        for ip in ips:
            result = _check_ip(ip, key)
            if result is not None:
                db.set_threat(ip, result)
                score = result["abuse_score"]
                if score > 0:
                    level = "MALICIOUS" if score >= 75 else "SUSPICIOUS" if score >= 25 else "low"
                    print(f"[threat] {ip} → score {score} ({level})")
            time.sleep(IP_WAIT)

        time.sleep(CYCLE_WAIT)
