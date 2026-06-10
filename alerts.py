"""
alerts.py — Alert rules engine.

Called each collector cycle via evaluate(connections).  Maintains
module-level sets of seen IPs and processes so new_ip / new_process
rules only fire once per lifetime of the process.

Rule condition and action fields are stored as JSON strings in the DB:
  condition: {"code":"CN"} | {"min_score":75} | "{}" for new_ip/new_process
  action:    {"type":"desktop"} | {"type":"webhook","url":"https://..."}
             | {"type":"slack","url":"https://hooks.slack.com/..."} | {"type":"email","to":"user@example.com"}
"""

import json
import smtplib
import threading
import urllib.request
from email.mime.text import MIMEText
import db

_lock        = threading.Lock()
_seen_ips:   set[str] = set()
_seen_procs: set[str] = set()

_smtp_config: dict = {}   # set by configure_smtp()


def configure_smtp(host: str, port: int, user: str, password: str, from_addr: str):
    global _smtp_config
    _smtp_config = {"host": host, "port": port, "user": user,
                    "password": password, "from": from_addr}


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
    atype = act.get("type", "desktop")
    ip    = conn.get("ip", "?")

    if atype == "webhook" and act.get("url"):
        _fire_webhook(act["url"], {
            "id": eid, "msg": msg, "ip": ip, "rule_type": rule["rule_type"],
        })
    elif atype == "slack" and act.get("url"):
        _fire_slack(act["url"], msg, rule["rule_type"], ip)
    elif atype == "email" and act.get("to"):
        _fire_email(act["to"], f"tracemap alert: {rule['rule_type']} — {ip}", msg)


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


def _fire_slack(url: str, msg: str, rule_type: str, ip: str):
    payload = {
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn",
             "text": f"*[tracemap alert]* `{rule_type.upper()}`\n{msg}"}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"IP: `{ip}`"}]},
        ]
    }
    _fire_webhook(url, payload)


def _fire_email(to: str, subject: str, body: str):
    if not _smtp_config:
        print("[alerts] Email skipped — SMTP not configured")
        return
    try:
        msg_obj = MIMEText(body, "plain")
        msg_obj["Subject"] = subject
        msg_obj["From"]    = _smtp_config.get("from", "tracemap@localhost")
        msg_obj["To"]      = to
        port = _smtp_config.get("port", 587)
        with smtplib.SMTP(_smtp_config["host"], port, timeout=10) as s:
            s.starttls()
            if _smtp_config.get("user"):
                s.login(_smtp_config["user"], _smtp_config.get("password", ""))
            s.sendmail(msg_obj["From"], [to], msg_obj.as_string())
        print(f"[alerts] Email sent to {to}")
    except Exception as e:
        print(f"[alerts] Email to {to} failed: {e}")


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
