import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import db

TEST_PORT = 19999


class TestServerRouting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Temp DB
        cls.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.tmp.close()
        cls.db_patch = patch("db.DB_PATH", Path(cls.tmp.name))
        cls.db_patch.start()
        db.init_db()

        # Seed DB with one connection log entry for history/threat endpoints
        db.log_connections([{"ip": "8.8.8.8", "port": "443",
                             "local_port": "12345", "process": "test"}])

        # Stub collector state (no real background thread needed)
        import collector
        collector._connections = [{
            "ip": "8.8.8.8", "port": "443", "local_port": "12345",
            "process": "test", "country": "US", "countryCode": "US",
            "city": "Mountain View", "lat": 37.4, "lon": -122.0,
            "org": "Google LLC", "isp": "Google",
        }]
        collector._host_geo = {
            "lat": 40.0, "lon": -74.0, "query": "1.2.3.4",
            "city": "Test City", "country": "US",
        }
        collector._last_updated = time.time()

        # Start server on test port
        import server
        server.PORT = TEST_PORT
        cls.server_thread = threading.Thread(target=server.run, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.db_patch.stop()
        os.unlink(cls.tmp.name)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get(self, path):
        conn = http.client.HTTPConnection("localhost", TEST_PORT, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, resp.getheader("Content-Type", ""), body

    def _post(self, path):
        conn = http.client.HTTPConnection("localhost", TEST_PORT, timeout=5)
        conn.request("POST", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    # ── HTML routes ───────────────────────────────────────────────────────────

    def test_root_returns_200(self):
        status, _, _ = self._get("/")
        self.assertEqual(status, 200)

    def test_root_content_type_html(self):
        _, ct, _ = self._get("/")
        self.assertIn("text/html", ct)

    def test_root_body_is_html(self):
        _, _, body = self._get("/")
        self.assertIn(b"<!DOCTYPE html>", body)

    def test_index_html_alias(self):
        status, _, body = self._get("/index.html")
        self.assertEqual(status, 200)
        self.assertIn(b"<!DOCTYPE html>", body)

    # ── /api/connections ──────────────────────────────────────────────────────

    def test_connections_status_200(self):
        status, _, _ = self._get("/api/connections")
        self.assertEqual(status, 200)

    def test_connections_content_type_json(self):
        _, ct, _ = self._get("/api/connections")
        self.assertIn("application/json", ct)

    def test_connections_has_required_keys(self):
        _, _, body = self._get("/api/connections")
        data = json.loads(body)
        for key in ("connections", "host", "last_updated", "threat_enabled"):
            self.assertIn(key, data)

    def test_connections_returns_seeded_ip(self):
        _, _, body = self._get("/api/connections")
        data = json.loads(body)
        ips = [c["ip"] for c in data["connections"]]
        self.assertIn("8.8.8.8", ips)

    def test_connections_threat_enabled_is_bool(self):
        _, _, body = self._get("/api/connections")
        data = json.loads(body)
        self.assertIsInstance(data["threat_enabled"], bool)

    # ── /api/history/<ip> ─────────────────────────────────────────────────────

    def test_history_status_200(self):
        status, _, _ = self._get("/api/history/8.8.8.8")
        self.assertEqual(status, 200)

    def test_history_shape(self):
        _, _, body = self._get("/api/history/8.8.8.8")
        data = json.loads(body)
        self.assertIn("ip", data)
        self.assertIn("events", data)
        self.assertIn("first_seen", data)

    def test_history_correct_ip(self):
        _, _, body = self._get("/api/history/8.8.8.8")
        data = json.loads(body)
        self.assertEqual(data["ip"], "8.8.8.8")

    def test_history_has_events(self):
        _, _, body = self._get("/api/history/8.8.8.8")
        data = json.loads(body)
        self.assertGreater(len(data["events"]), 0)

    def test_history_unknown_ip_returns_empty(self):
        _, _, body = self._get("/api/history/99.99.99.99")
        data = json.loads(body)
        self.assertEqual(data["events"], [])
        self.assertIsNone(data["first_seen"])

    # ── /api/threat/<ip> ──────────────────────────────────────────────────────

    def test_threat_status_200(self):
        status, _, _ = self._get("/api/threat/8.8.8.8")
        self.assertEqual(status, 200)

    def test_threat_no_data_returns_empty_dict(self):
        _, _, body = self._get("/api/threat/99.99.99.99")
        data = json.loads(body)
        self.assertIsInstance(data, dict)
        self.assertEqual(data, {})

    def test_threat_with_cached_data(self):
        db.set_threat("8.8.8.8", {"abuse_score": 55, "reports": 3})
        _, _, body = self._get("/api/threat/8.8.8.8")
        data = json.loads(body)
        self.assertEqual(data["abuse_score"], 55)
        self.assertEqual(data["reports"], 3)

    # ── /api/traceroute/<ip> GET ──────────────────────────────────────────────

    def test_traceroute_get_not_found(self):
        status, _, body = self._get("/api/traceroute/99.99.99.99")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "not_found")

    def test_traceroute_get_with_cached_result(self):
        db.store_traceroute("8.8.8.8", [{"hop": 1, "ip": "1.1.1.1", "rtt_ms": 5.0}])
        _, _, body = self._get("/api/traceroute/8.8.8.8")
        data = json.loads(body)
        self.assertIn("hops", data)

    # ── /api/traceroute/<ip> POST ─────────────────────────────────────────────

    def test_traceroute_post_returns_status(self):
        with patch("traceroute.start", return_value="running") as mock_start:
            status, body = self._post("/api/traceroute/1.2.3.4")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("status", data)
        mock_start.assert_called_once_with("1.2.3.4")

    def test_traceroute_post_cached_returns_cached(self):
        with patch("traceroute.start", return_value="cached"):
            _, body = self._post("/api/traceroute/1.2.3.4")
        data = json.loads(body)
        self.assertEqual(data["status"], "cached")

    # ── 404s ─────────────────────────────────────────────────────────────────

    def test_unknown_get_path_returns_404(self):
        status, _, _ = self._get("/does/not/exist")
        self.assertEqual(status, 404)

    def test_unknown_post_path_returns_404(self):
        status, _ = self._post("/not/an/endpoint")
        self.assertEqual(status, 404)

    def test_api_prefix_without_subpath_returns_404(self):
        status, _, _ = self._get("/api/")
        self.assertEqual(status, 404)
