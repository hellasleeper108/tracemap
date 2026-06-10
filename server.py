"""
server.py — HTTP server, request routing, and JSON API.
"""

import json
from collections import Counter
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import collector
import db
import threat
import traceroute as tr

PORT       = 9999
STATIC_DIR = Path(__file__).parent / "static"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # silence access log

    def do_GET(self):
        path = self.path.split("?")[0]  # strip query string

        if path in ("/", "/index.html"):
            self._serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")

        elif path == "/api/connections":
            self._json(collector.get_state())

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
            self._json({
                "total_connections": len(conns),
                "unique_countries":  len(set(countries)),
                "unique_ips":        len({c["ip"] for c in conns if c.get("ip")}),
                "top_processes":     [{"name": n, "count": v} for n, v in Counter(procs).most_common(5)],
                "top_orgs":          [{"name": n, "count": v} for n, v in Counter(orgs).most_common(5)],
                "top_countries":     [{"code": n, "count": v} for n, v in Counter(countries).most_common(5)],
                "threat_summary":    threat_summary,
            })

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = self.path.split("?")[0]
        if path.startswith("/api/traceroute/"):
            ip     = path.removeprefix("/api/traceroute/")
            status = tr.start(ip)
            self._json({"status": status})
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_file(self, path: Path, content_type: str):
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            return
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


def run():
    HTTPServer.allow_reuse_address = True
    httpd = HTTPServer(("localhost", PORT), _Handler)
    httpd.serve_forever()
