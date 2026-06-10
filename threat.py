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

VT_TTL      = 24 * 3600
SHODAN_TTL  = 24 * 3600
VT_IP_WAIT  = 16          # VirusTotal free tier: 4 req/min → 15s+ per request


def _api_key() -> str | None:
    return os.environ.get("ABUSEIPDB_KEY")


def _vt_key() -> str | None:
    return os.environ.get("VIRUSTOTAL_KEY")


def _shodan_key() -> str | None:
    return os.environ.get("SHODAN_KEY")


def is_enabled() -> bool:
    return bool(_api_key())


def vt_enabled() -> bool:
    return bool(_vt_key())


def shodan_enabled() -> bool:
    return bool(_shodan_key())


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


def _check_virustotal(ip: str, key: str) -> dict | None:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(url, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
        stats = body["data"]["attributes"]["last_analysis_stats"]
        mal   = stats.get("malicious",  0)
        sus   = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = int((mal + sus) / total * 100)
        return {"score": score, "malicious": mal, "suspicious": sus, "total": total}
    except urllib.error.HTTPError as e:
        if e.code == 429:
            time.sleep(60)
        elif e.code != 404:
            print(f"[threat] VirusTotal HTTP {e.code} for {ip}")
    except Exception as e:
        print(f"[threat] VirusTotal error for {ip}: {e}")
    return None


def _check_shodan(ip: str, key: str) -> dict | None:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = json.loads(resp.read())
        tags  = body.get("tags",  [])
        vulns = len(body.get("vulns", {}))
        score = min(100, vulns * 10
                    + (40 if "malware" in tags else 0)
                    + (20 if "botnet"  in tags else 0))
        return {"score": score, "tags": tags, "vulns": vulns,
                "ports": body.get("ports", [])}
    except urllib.error.HTTPError as e:
        if e.code not in (400, 404):
            print(f"[threat] Shodan HTTP {e.code} for {ip}")
    except Exception as e:
        print(f"[threat] Shodan error for {ip}: {e}")
    return None


def multi_source_loop():
    """Background loop for VirusTotal and Shodan enrichment."""
    vt_key     = _vt_key()
    sh_key     = _shodan_key()
    if not vt_key and not sh_key:
        print("[threat] No VT/Shodan keys — multi-source threat intel disabled.")
        return
    sources = ", ".join(filter(None, [
        "VirusTotal" if vt_key else "",
        "Shodan"     if sh_key else "",
    ]))
    print(f"[threat] Multi-source enabled: {sources}")
    while True:
        if vt_key:
            for ip in db.get_ips_needing_source_check("virustotal", VT_TTL, limit=3):
                result = _check_virustotal(ip, vt_key)
                if result is not None:
                    db.set_threat_source(ip, "virustotal", result["score"], result)
                time.sleep(VT_IP_WAIT)
        if sh_key:
            for ip in db.get_ips_needing_source_check("shodan", SHODAN_TTL, limit=5):
                result = _check_shodan(ip, sh_key)
                if result is not None:
                    db.set_threat_source(ip, "shodan", result["score"], result)
                time.sleep(IP_WAIT)
        time.sleep(CYCLE_WAIT)
