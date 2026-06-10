"""
report.py — Daily threat summary reports.
Generates a JSON summary at local midnight; exposes via /api/reports.
"""

import json
import threading
import time
from collections import Counter
from pathlib import Path
import db

REPORTS_DIR = Path.home() / ".local" / "share" / "tracemap" / "reports"

_enabled = True
_lock    = threading.Lock()


def disable():
    global _enabled
    _enabled = False


def _generate() -> dict:
    now    = int(time.time())
    start  = now - 86400
    conns  = db.export_connections(since=start)
    threats = db.export_threats()

    unique_ips = len({c["ip"] for c in conns})
    countries  = Counter(c.get("countryCode", "") for c in conns if c.get("countryCode"))
    processes  = Counter(c.get("process", "")     for c in conns if c.get("process"))
    conn_ips   = {c["ip"] for c in conns}
    active_threats = [t for t in threats if t["ip"] in conn_ips]
    active_threats.sort(key=lambda t: t.get("abuse_score", 0), reverse=True)

    return {
        "date":          time.strftime("%Y-%m-%d"),
        "generated_at":  now,
        "period_start":  start,
        "period_end":    now,
        "unique_ips":    unique_ips,
        "total_events":  len(conns),
        "malicious_ips": len(active_threats),
        "top_countries": [{"code": k, "count": v} for k, v in countries.most_common(5)],
        "top_processes": [{"name": k, "count": v} for k, v in processes.most_common(5)],
        "top_threats":   [
            {"ip": t["ip"], "score": t.get("abuse_score", 0),
             "country": t.get("country", "")}
            for t in active_threats[:10]
        ],
    }


def save_report(r: dict):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"{r['date']}.json"
    path.write_text(json.dumps(r, indent=2))
    print(f"[report] Saved daily report → {path}")


def list_reports() -> list[str]:
    if not REPORTS_DIR.exists():
        return []
    return sorted((p.stem for p in REPORTS_DIR.glob("*.json")), reverse=True)


def get_report(date_str: str) -> dict | None:
    path = REPORTS_DIR / f"{date_str}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def summary_loop():
    """Sleep until local midnight, then generate and save a report."""
    while True:
        now      = time.localtime()
        midnight = time.mktime((now.tm_year, now.tm_mon, now.tm_mday + 1,
                                0, 0, 0, 0, 0, -1))
        time.sleep(max(1, midnight - time.time()))
        if _enabled:
            try:
                save_report(_generate())
            except Exception as e:
                print(f"[report] Daily report error: {e}")
