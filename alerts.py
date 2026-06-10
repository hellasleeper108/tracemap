"""
alerts.py — Alert rules engine.

Called each collector cycle via evaluate(connections).  Maintains
module-level sets of seen IPs and processes so new_ip / new_process
rules only fire once per lifetime of the process.

Rule condition and action fields are stored as JSON strings in the DB:
  condition: {"code":"CN"} | {"min_score":75} | "{}" for new_ip/new_process
  action:    {"type":"desktop"} | {"type":"webhook","url":"https://..."}
"""

import json
import threading
import urllib.request
import db

_lock        = threading.Lock()
_seen_ips:   set[str] = set()
_seen_procs: set[str] = set()


def load_rules_from_file(path: str):
    """Bootstrap alert_rules table from a JSON file at startup."""
    try:
        with open(path) as f:
            rules = json.load(f)
        for r in rules:
            cond = r.get("condition", {})
            act  = r.get("action",    {"type": "desktop"})
            db.create_alert_rule(
                rule_type = r["rule_type"],
                condition = json.dumps(cond) if isinstance(cond, dict) else str(cond),
                action    = json.dumps(act)  if isinstance(act,  dict) else str(act),
            )
        print(f"[alerts] Loaded {len(rules)} rules from {path}")
    except Exception as e:
        print(f"[alerts] Failed to load rules from {path}: {e}")


def _fire(rule: dict, conn: dict):
    msg = (
        f"[{rule['rule_type'].upper()}] {conn.get('ip', '?')} "
        f"({conn.get('country', '?')}) via {conn.get('process', '?')}"
    )
    print(f"[alerts] {msg}")
    eid = db.create_alert_event(
        rule_id   = rule["id"],
        rule_type = rule["rule_type"],
        ip        = conn.get("ip", ""),
        msg       = msg,
    )
    try:
        act = json.loads(rule.get("action") or '{"type":"desktop"}')
    except Exception:
        act = {"type": "desktop"}
    if act.get("type") == "webhook" and act.get("url"):
        _fire_webhook(act["url"], {
            "id": eid, "msg": msg,
            "ip": conn.get("ip"), "rule_type": rule["rule_type"],
        })


def _fire_webhook(url: str, payload: dict):
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[alerts] Webhook to {url} failed: {e}")


def evaluate(connections: list[dict]):
    """Evaluate all enabled rules against the current connection list."""
    rules = db.get_alert_rules(enabled_only=True)
    if not rules:
        return

    with _lock:
        current_ips   = {c["ip"]              for c in connections}
        current_procs = {c.get("process", "")  for c in connections if c.get("process")}
        new_ips       = current_ips   - _seen_ips
        new_procs     = current_procs - _seen_procs
        _seen_ips.update(current_ips)
        _seen_procs.update(current_procs)

    fired: set[tuple] = set()  # (rule_id, ip) — deduplicate within this cycle

    for conn in connections:
        for rule in rules:
            key = (rule["id"], conn["ip"])
            if key in fired:
                continue
            triggered = False
            try:
                cond = json.loads(rule.get("condition") or "{}")
            except Exception:
                cond = {}

            match rule["rule_type"]:
                case "country":
                    cc = (cond.get("code") or rule.get("condition") or "").upper()
                    triggered = conn.get("countryCode", "").upper() == cc
                case "threat_score":
                    try:
                        threshold = int(cond.get("min_score", rule.get("condition", 75)))
                        triggered = (conn.get("abuse_score") or 0) >= threshold
                    except (ValueError, TypeError):
                        pass
                case "new_ip":
                    triggered = conn["ip"] in new_ips
                case "new_process":
                    triggered = bool(conn.get("process")) and conn["process"] in new_procs

            if triggered:
                _fire(rule, conn)
                fired.add(key)
