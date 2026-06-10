"""
server.py — HTTP server, request routing, and JSON API.
"""

import json
from collections import Counter
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import time
import collector
import db
import threat
import firewall
import agent
import traceroute as tr

PORT        = 9999
STATIC_DIR  = Path(__file__).parent / "static"
AGENT_MODE  = False   # set True by --agent flag; enables API-key auth
HUB_MODE    = False   # set True by --hub flag; merges remote connections


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # silence access log

    def _check_agent_auth(self) -> bool:
        if not AGENT_MODE:
            return True
        return agent.check_auth(self.headers.get("X-Agent-Key"))

    def _parse_path(self) -> tuple[str, dict]:
        """Return (path_without_qs, {param: [val, ...]} dict)."""
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def do_GET(self):
        if not self._check_agent_auth():
            return self._error(401, "unauthorized")
        path, params = self._parse_path()

        if path in ("/", "/index.html"):
            self._serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")

        elif path == "/api/connections":
            # Hub mode: merge local + remote-agent connections
            if agent.is_hub():
                local   = collector.get_state()
                remote  = agent.get_merged_connections()
                for c in local["connections"]:
                    c.setdefault("agent_label", "local")
                self._json({
                    **local,
                    "connections": local["connections"] + remote,
                    "hub_agents":  agent.get_agent_status(),
                })
            else:
                self._json(collector.get_state())

        elif path.startswith("/api/connections/at/"):
            try:
                ts = int(path.removeprefix("/api/connections/at/"))
            except ValueError:
                return self._error(400, "invalid timestamp")
            window = int((params.get("window") or ["300"])[0])
            self._json(db.get_connections_at(ts, window=window))

        elif path == "/api/history/timeline":
            window = int((params.get("window") or ["24"])[0])
            self._json(db.get_timeline(window_hours=window))

        elif path.startswith("/api/history/"):
            ip = path.removeprefix("/api/history/")
            rows = db.get_history(ip)
            first = db.get_first_seen(ip)
            self._json({"ip": ip, "first_seen": first, "events": rows})

        elif path.startswith("/api/threat/"):
            ip = path.removeprefix("/api/threat/")
            self._json(db.get_threat(ip) or {})

        elif path.startswith("/api/traceroute/"):
            ip = path.removeprefix("/api/traceroute/")
            self._json(tr.get_result(ip))

        elif path == "/api/firewall/status":
            self._json({
                "available": firewall.is_available(),
                "blocked":   firewall.get_blocked(),
            })

        elif path == "/api/blocked":
            self._json(firewall.get_blocked())

        elif path == "/api/agents":
            self._json(agent.get_agent_status())

        elif path == "/api/stats":
            conns     = collector.get_state()["connections"]
            procs     = [c["process"]     for c in conns if c.get("process")]
            orgs      = [c["org"]         for c in conns if c.get("org")]
            countries = [c["countryCode"] for c in conns if c.get("countryCode")]
            threat_summary = {"malicious": 0, "suspicious": 0, "low_risk": 0, "clean": 0}
            for c in conns:
                score = c.get("abuse_score")
                if score is None:
                    continue
                if score >= 75:   threat_summary["malicious"]  += 1
                elif score >= 25: threat_summary["suspicious"] += 1
                elif score >= 1:  threat_summary["low_risk"]   += 1
                else:             threat_summary["clean"]      += 1
            containers = [c["container"] for c in conns if c.get("container")]
            bw_total_recv = sum(c.get("recv_bps", 0) for c in conns)
            bw_total_send = sum(c.get("send_bps", 0) for c in conns)
            bw_leaders = sorted(
                [{"ip": c["ip"], "recv_bps": c.get("recv_bps", 0),
                  "send_bps": c.get("send_bps", 0)} for c in conns],
                key=lambda x: x["recv_bps"] + x["send_bps"], reverse=True
            )[:5]
            self._json({
                "total_connections": len(conns),
                "unique_countries":  len(set(countries)),
                "unique_ips":        len({c["ip"] for c in conns if c.get("ip")}),
                "top_processes":     [{"name": n, "count": v} for n, v in Counter(procs).most_common(5)],
                "top_orgs":          [{"name": n, "count": v} for n, v in Counter(orgs).most_common(5)],
                "top_countries":     [{"code": n, "count": v} for n, v in Counter(countries).most_common(5)],
                "top_containers":    [{"name": n, "count": v} for n, v in Counter(containers).most_common(5)],
                "threat_summary":    threat_summary,
                "tor_count":         sum(1 for c in conns if c.get("is_tor")),
                "vpn_count":         sum(1 for c in conns if c.get("is_vpn")),
                "blocked_count":     sum(1 for c in conns if c.get("is_blocked")),
                "firewall_available": firewall.is_available(),
                "bw_total_recv":     bw_total_recv,
                "bw_total_send":     bw_total_send,
                "bw_leaders":        bw_leaders,
            })

        elif path == "/api/alerts/rules":
            self._json(db.get_alert_rules(enabled_only=False))

        elif path == "/api/alerts/events":
            limit = int((params.get("limit") or ["50"])[0])
            self._json(db.get_alert_events(limit=limit))

        elif path == "/api/alerts/pending":
            self._json(db.pop_pending_alerts())

        elif path == "/api/alerts/unread":
            self._json({"count": db.get_unread_alert_count()})

        else:
            self._error(404, "not found")

    def do_POST(self):
        if not self._check_agent_auth():
            return self._error(401, "unauthorized")
        path, _ = self._parse_path()

        if path.startswith("/api/traceroute/"):
            ip     = path.removeprefix("/api/traceroute/")
            status = tr.start(ip)
            self._json({"status": status})

        elif path == "/api/alerts/rules":
            body = self._read_json_body()
            rule_type = body.get("rule_type", "")
            if rule_type not in ("country", "threat_score", "new_ip", "new_process"):
                return self._error(400, "invalid rule_type")
            cond = body.get("condition", {})
            act  = body.get("action",    {"type": "desktop"})
            rid  = db.create_alert_rule(
                rule_type = rule_type,
                condition = json.dumps(cond) if isinstance(cond, dict) else str(cond),
                action    = json.dumps(act)  if isinstance(act,  dict) else str(act),
            )
            self._json(db.get_alert_rule(rid))

        elif path == "/api/alerts/read":
            body = self._read_json_body()
            ids  = body.get("ids")  # list or None (None = mark all)
            db.mark_alerts_read(ids)
            self._json({"ok": True})

        elif path.startswith("/api/block/"):
            ip = path.removeprefix("/api/block/")
            if not ip:
                return self._error(400, "missing ip")
            self._json(firewall.block(ip))

        else:
            self._error(404, "not found")

    def do_DELETE(self):
        if not self._check_agent_auth():
            return self._error(401, "unauthorized")
        path, _ = self._parse_path()

        if path.startswith("/api/alerts/rules/"):
            try:
                rid = int(path.removeprefix("/api/alerts/rules/"))
            except ValueError:
                return self._error(400, "invalid id")
            db.delete_alert_rule(rid)
            self._json({"ok": True})

        elif path.startswith("/api/block/"):
            ip = path.removeprefix("/api/block/")
            if not ip:
                return self._error(400, "missing ip")
            self._json(firewall.unblock(ip))

        else:
            self._error(404, "not found")

    def do_PATCH(self):
        if not self._check_agent_auth():
            return self._error(401, "unauthorized")
        path, _ = self._parse_path()

        if path.startswith("/api/alerts/rules/"):
            try:
                rid = int(path.removeprefix("/api/alerts/rules/"))
            except ValueError:
                return self._error(400, "invalid id")
            body = self._read_json_body()
            db.update_alert_rule(rid, **{k: v for k, v in body.items()
                                         if k in ("enabled", "condition", "action")})
            rule = db.get_alert_rule(rid)
            if rule is None:
                return self._error(404, "rule not found")
            self._json(rule)

        else:
            self._error(404, "not found")

    def _serve_file(self, path: Path, content_type: str):
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            return self._error(404, "file not found")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data: dict | list):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code: int, msg: str):
        body = json.dumps({"error": msg}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run(host: str = "localhost"):
    HTTPServer.allow_reuse_address = True
    httpd = HTTPServer((host, PORT), _Handler)
    httpd.serve_forever()
