"""
server.py — HTTP server, request routing, and JSON API.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import collector
import db
import threat

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
