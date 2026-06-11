"""
server.py — HTTP server, request routing, and JSON API.
"""

import base64
import csv
import hashlib
import io
import json
import struct
import threading
import time
from collections import Counter
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import collector
import db
import threat
import firewall
import agent
import traceroute as tr

# RFC 6455 WebSocket GUID
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_encode_frame(payload: bytes) -> bytes:
    """Encode a WebSocket text frame (RFC 6455 §5.2).

    Server frames are NOT masked. Byte 0: 0x81 (FIN=1, opcode=1 text).
    """
    length = len(payload)
    if length <= 125:
        header = struct.pack("BB", 0x81, length)
    elif length <= 65535:
        header = struct.pack("!BBH", 0x81, 126, length)
    else:
        header = struct.pack("!BBQ", 0x81, 127, length)
    return header + payload

REPORTS_DIR = Path.home() / ".local" / "share" / "tracemap" / "reports"

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
        path, params = self._parse_path()

        # /metrics is unauthenticated — Prometheus scrapers don't use API keys
        if path == "/metrics":
            return self._prometheus_metrics()

        if not self._check_agent_auth():
            return self._error(401, "unauthorized")

        # WebSocket upgrade check
        if self.headers.get("Upgrade", "").lower() == "websocket":
            return self._ws_upgrade()

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
                "total":             len(conns),
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

        elif path == "/api/timeline":
            window = int((params.get("window") or ["24"])[0])
            self._json(db.get_timeline(window_hours=window))

        elif path == "/api/threats":
            self._json(db.get_all_threats())

        elif path == "/api/rules":
            self._json(db.get_alert_rules(enabled_only=False))

        elif path.startswith("/api/notes/"):
            ip = path.removeprefix("/api/notes/")
            self._json({"ip": ip, "note": db.get_note(ip)})

        elif path == "/api/export/connections":
            fmt = (params.get("format") or ["json"])[0]
            rows = db.get_export_connections()
            if fmt == "csv":
                self._csv(rows, ["ip", "port", "process", "seen_at"])
            else:
                self._json(rows)

        elif path == "/api/export/threats":
            self._json(db.get_all_threats())

        elif path == "/api/reports":
            if REPORTS_DIR.exists():
                files = sorted(REPORTS_DIR.glob("*.json"), reverse=True)
                self._json([{"file": f.name, "date": f.stem} for f in files[:50]])
            else:
                self._json([])

        elif path == "/api/db/stats":
            self._json(db.get_db_stats())

        elif path == "/api/geo/status":
            self._json({"source": "ip-api.com"})

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

        elif path == "/api/rules":
            body = self._read_json_body()
            rule_type = body.get("type", "")
            if rule_type not in ("country", "threat_score", "new_ip", "new_process"):
                return self._error(400, "invalid type")
            value = body.get("value", "")
            if rule_type == "country":
                cond = json.dumps({"code": value})
            elif rule_type == "threat_score":
                cond = json.dumps({"min_score": value})
            else:
                cond = "{}"
            act = body.get("action", {"type": "desktop"})
            rid = db.create_alert_rule(
                rule_type=rule_type,
                condition=cond,
                action=json.dumps(act) if isinstance(act, dict) else str(act),
            )
            rule = db.get_alert_rule(rid)
            self._json_201(rule)

        elif path.startswith("/api/notes/"):
            ip = path.removeprefix("/api/notes/")
            body = self._read_json_body()
            db.set_note(ip, body.get("note", ""))
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

    def _prometheus_metrics(self):
        conns = collector.get_state()["connections"]
        malicious  = sum(1 for c in conns if (c.get("abuse_score") or 0) >= 75)
        suspicious = sum(1 for c in conns if 25 <= (c.get("abuse_score") or 0) < 75)
        tor_count  = sum(1 for c in conns if c.get("is_tor"))
        bw_recv    = sum(c.get("recv_bps", 0) for c in conns)
        bw_send    = sum(c.get("send_bps", 0) for c in conns)
        unique_ips = len({c["ip"] for c in conns if c.get("ip")})
        blocked    = len(db.get_blocked_ips())

        lines = [
            "# HELP tracemap_connections_total Current number of active connections",
            "# TYPE tracemap_connections_total gauge",
            f"tracemap_connections_total {len(conns)}",
            "# HELP tracemap_unique_ips_total Current number of unique IPs",
            "# TYPE tracemap_unique_ips_total gauge",
            f"tracemap_unique_ips_total {unique_ips}",
            "# HELP tracemap_threats_malicious Connections with abuse_score >= 75",
            "# TYPE tracemap_threats_malicious gauge",
            f"tracemap_threats_malicious {malicious}",
            "# HELP tracemap_threats_suspicious Connections with abuse_score 25-74",
            "# TYPE tracemap_threats_suspicious gauge",
            f"tracemap_threats_suspicious {suspicious}",
            "# HELP tracemap_blocked_ips_total Number of blocked IPs",
            "# TYPE tracemap_blocked_ips_total gauge",
            f"tracemap_blocked_ips_total {blocked}",
            "# HELP tracemap_tor_connections Connections flagged as Tor exit nodes",
            "# TYPE tracemap_tor_connections gauge",
            f"tracemap_tor_connections {tor_count}",
            "# HELP tracemap_bw_recv_bytes_total Sum of recv_bps across all connections",
            "# TYPE tracemap_bw_recv_bytes_total gauge",
            f"tracemap_bw_recv_bytes_total {bw_recv}",
            "# HELP tracemap_bw_send_bytes_total Sum of send_bps across all connections",
            "# TYPE tracemap_bw_send_bytes_total gauge",
            f"tracemap_bw_send_bytes_total {bw_send}",
        ]
        body = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ws_upgrade(self):
        """Handle WebSocket upgrade and push loop for /ws/connections."""
        path, _ = self._parse_path()
        if path != "/ws/connections":
            self._error(404, "not found")
            return

        key = self.headers.get("Sec-WebSocket-Key", "").strip()
        if not key:
            self._error(400, "missing Sec-WebSocket-Key")
            return

        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()
        ).decode()

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()

        while True:
            try:
                state   = collector.get_state()
                payload = json.dumps(state).encode("utf-8")
                frame   = _ws_encode_frame(payload)
                self.wfile.write(frame)
                self.wfile.flush()
                time.sleep(1)
            except Exception:
                break

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

    def _json_201(self, data: dict | list):
        body = json.dumps(data).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _csv(self, rows: list[dict], fields: list[str]):
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
        body = buf.getvalue().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Length", str(len(body)))
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
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer.daemon_threads = True   # keep WS threads from blocking shutdown
    httpd = ThreadingHTTPServer((host, PORT), _Handler)
    httpd.serve_forever()
