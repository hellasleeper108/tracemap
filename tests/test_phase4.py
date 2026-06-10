"""
Phase 4 tests — notes, retention, aggregation, export, geo helpers,
report generation, new server endpoints, alert notification channels.
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import db

TEST_PORT = 29999


# ── DB: notes ─────────────────────────────────────────────────────────────────

class TestNotes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_get_note_empty_default(self):
        self.assertEqual(db.get_note("1.2.3.4"), "")

    def test_set_and_get_note(self):
        db.set_note("8.8.8.8", "Google DNS — safe")
        self.assertEqual(db.get_note("8.8.8.8"), "Google DNS — safe")

    def test_update_note(self):
        db.set_note("1.1.1.1", "first")
        db.set_note("1.1.1.1", "updated")
        self.assertEqual(db.get_note("1.1.1.1"), "updated")

    def test_empty_note_allowed(self):
        db.set_note("8.8.8.8", "text")
        db.set_note("8.8.8.8", "")
        self.assertEqual(db.get_note("8.8.8.8"), "")


# ── DB: config ────────────────────────────────────────────────────────────────

class TestDbConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_default_returned_when_missing(self):
        self.assertEqual(db.get_config("missing_key", "default"), "default")

    def test_set_and_get_config(self):
        db.set_config("history_days", "30")
        self.assertEqual(db.get_config("history_days"), "30")

    def test_update_config(self):
        db.set_config("key", "v1")
        db.set_config("key", "v2")
        self.assertEqual(db.get_config("key"), "v2")


# ── DB: retention / prune ─────────────────────────────────────────────────────

class TestRetention(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def _insert_old(self, days_ago: int):
        ts = int(time.time()) - days_ago * 86400
        import sqlite3
        with sqlite3.connect(self.tmp.name) as c:
            c.execute(
                "INSERT INTO connections_log (ip,port,local_port,process,seen_at) VALUES (?,?,?,?,?)",
                ("1.2.3.4", "443", "5000", "test", ts)
            )

    def test_prune_removes_old(self):
        self._insert_old(60)
        db.prune_old_connections(days=30)
        self.assertEqual(db.get_history("1.2.3.4"), [])

    def test_prune_keeps_recent(self):
        self._insert_old(5)
        db.prune_old_connections(days=30)
        self.assertEqual(len(db.get_history("1.2.3.4")), 1)

    def test_get_db_stats_returns_dict(self):
        stats = db.get_db_stats()
        self.assertIn("table_counts", stats)
        self.assertIn("db_size_bytes", stats)
        self.assertIn("oldest_entry", stats)
        self.assertIn("connections_log", stats["table_counts"])


# ── DB: hourly aggregation ────────────────────────────────────────────────────

class TestHourlyAggregation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def _insert_at(self, ip: str, hours_ago: int):
        ts = int(time.time()) - hours_ago * 3600
        import sqlite3
        with sqlite3.connect(self.tmp.name) as c:
            c.execute(
                "INSERT INTO connections_log (ip,port,local_port,process,seen_at) VALUES (?,?,?,?,?)",
                (ip, "443", "5000", "test", ts)
            )

    def test_aggregate_moves_old_rows(self):
        self._insert_at("1.2.3.4", 48)
        db.aggregate_old_connections(cutoff_hours=24)
        self.assertEqual(db.get_history("1.2.3.4"), [])

    def test_aggregate_keeps_recent(self):
        self._insert_at("1.2.3.4", 1)
        db.aggregate_old_connections(cutoff_hours=24)
        self.assertEqual(len(db.get_history("1.2.3.4")), 1)

    def test_timeline_uses_aggregates(self):
        self._insert_at("1.2.3.4", 48)
        db.aggregate_old_connections(cutoff_hours=24)
        tl = db.get_timeline(window_hours=72)
        total = sum(b["count"] for b in tl)
        self.assertGreater(total, 0)


# ── DB: export ────────────────────────────────────────────────────────────────

class TestExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()
        db.log_connections([{"ip": "8.8.8.8", "port": "443",
                             "local_port": "5000", "process": "test"}])

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_export_connections_returns_list(self):
        rows = db.export_connections()
        self.assertIsInstance(rows, list)
        self.assertGreater(len(rows), 0)

    def test_export_connections_since_filter(self):
        future = int(time.time()) + 9999
        rows = db.export_connections(since=future)
        self.assertEqual(rows, [])

    def test_export_threats_returns_list(self):
        rows = db.export_threats()
        self.assertIsInstance(rows, list)

    def test_export_threats_only_nonzero_scores(self):
        db.set_threat("8.8.8.8", {"abuse_score": 0, "reports": 0})
        rows = db.export_threats()
        self.assertFalse(any(r["ip"] == "8.8.8.8" for r in rows))
        db.set_threat("8.8.8.8", {"abuse_score": 80, "reports": 5})
        rows = db.export_threats()
        self.assertTrue(any(r["ip"] == "8.8.8.8" for r in rows))


# ── geo: flag + status ────────────────────────────────────────────────────────

import geo as geo_mod


class TestGeoHelpers(unittest.TestCase):
    def test_flag_us(self):
        f = geo_mod.flag("US")
        self.assertEqual(len(f), 2)  # two regional indicator chars
        self.assertEqual(f, "🇺🇸")

    def test_flag_gb(self):
        self.assertEqual(geo_mod.flag("GB"), "🇬🇧")

    def test_flag_empty_string(self):
        self.assertEqual(geo_mod.flag(""), "")

    def test_flag_wrong_length(self):
        self.assertEqual(geo_mod.flag("USA"), "")

    def test_geo_status_no_local_db(self):
        geo_mod.configure_geoip_db(None)
        s = geo_mod.get_geo_status()
        self.assertEqual(s["source"], "ip-api.com")
        self.assertIsNone(s["city_db"])

    def test_geo_status_with_local_db(self):
        geo_mod.configure_geoip_db("/fake/path/GeoLite2-City.mmdb")
        s = geo_mod.get_geo_status()
        self.assertEqual(s["source"], "local")
        geo_mod.configure_geoip_db(None)  # reset


# ── report ────────────────────────────────────────────────────────────────────

import report as report_mod


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()
        self.tmpdir = tempfile.mkdtemp()
        self.rp = patch("report.REPORTS_DIR", Path(self.tmpdir))
        self.rp.start()

    def tearDown(self):
        self.p.stop()
        self.rp.stop()
        os.unlink(self.tmp.name)
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        report_mod._enabled = True

    def test_list_reports_empty(self):
        self.assertEqual(report_mod.list_reports(), [])

    def test_save_and_list_report(self):
        r = {"date": "2026-01-01", "generated_at": 0, "period_start": 0,
             "period_end": 0, "unique_ips": 0, "total_events": 0,
             "malicious_ips": 0, "top_countries": [], "top_processes": [],
             "top_threats": []}
        report_mod.save_report(r)
        self.assertIn("2026-01-01", report_mod.list_reports())

    def test_get_report_roundtrip(self):
        r = {"date": "2026-02-15", "unique_ips": 42, "generated_at": 1234,
             "period_start": 0, "period_end": 0, "total_events": 10,
             "malicious_ips": 1, "top_countries": [], "top_processes": [],
             "top_threats": []}
        report_mod.save_report(r)
        got = report_mod.get_report("2026-02-15")
        self.assertEqual(got["unique_ips"], 42)

    def test_get_report_missing_returns_none(self):
        self.assertIsNone(report_mod.get_report("1900-01-01"))

    def test_disable_flag(self):
        report_mod.disable()
        self.assertFalse(report_mod._enabled)

    def test_generate_builds_summary(self):
        db.log_connections([{"ip": "8.8.8.8", "port": "443",
                             "local_port": "5000", "process": "curl"}])
        r = report_mod._generate()
        self.assertIn("date", r)
        self.assertIn("unique_ips", r)
        self.assertGreaterEqual(r["unique_ips"], 1)
        self.assertIn("top_processes", r)


# ── alerts: Slack + email dispatchers ─────────────────────────────────────────

import alerts as alerts_mod


class TestAlertDispatchers(unittest.TestCase):
    def setUp(self):
        alerts_mod._smtp_config = {}

    def tearDown(self):
        alerts_mod._smtp_config = {}

    def test_fire_slack_calls_webhook(self):
        with patch("alerts._fire_webhook") as mocked:
            alerts_mod._fire_slack("http://hooks.example.com", "msg", "country", "1.2.3.4")
        mocked.assert_called_once()
        args = mocked.call_args[0]
        self.assertEqual(args[0], "http://hooks.example.com")
        self.assertIn("blocks", args[1])

    def test_fire_email_skipped_without_smtp(self):
        with patch("smtplib.SMTP") as smtp_cls:
            alerts_mod._fire_email("user@example.com", "subj", "body")
        smtp_cls.assert_not_called()

    def test_configure_smtp_sets_config(self):
        alerts_mod.configure_smtp("smtp.example.com", 587, "user", "pass", "from@example.com")
        self.assertEqual(alerts_mod._smtp_config["host"], "smtp.example.com")
        self.assertEqual(alerts_mod._smtp_config["port"], 587)

    def test_fire_email_with_smtp_configured(self):
        alerts_mod.configure_smtp("smtp.example.com", 587, "user", "pass", "from@example.com")
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        with patch("smtplib.SMTP", return_value=mock_smtp):
            alerts_mod._fire_email("to@example.com", "subject", "body text")
        mock_smtp.sendmail.assert_called_once()


# ── Server: Phase 4 endpoints ─────────────────────────────────────────────────

class TestPhase4ServerEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.tmp.close()
        cls.db_patch = patch("db.DB_PATH", Path(cls.tmp.name))
        cls.db_patch.start()
        db.init_db()

        db.log_connections([{"ip": "8.8.8.8", "port": "443",
                             "local_port": "12345", "process": "test"}])

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

        cls.report_patch = patch("report.REPORTS_DIR", Path(tempfile.mkdtemp()))
        cls.report_patch.start()

        import server
        server.PORT = TEST_PORT
        cls.srv = threading.Thread(target=server.run, daemon=True)
        cls.srv.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.db_patch.stop()
        cls.report_patch.stop()
        os.unlink(cls.tmp.name)

    def _get(self, path):
        c = http.client.HTTPConnection("localhost", TEST_PORT, timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, body

    def _post(self, path, body=None):
        c = http.client.HTTPConnection("localhost", TEST_PORT, timeout=5)
        headers = {"Content-Type": "application/json"}
        c.request("POST", path,
                  body=json.dumps(body).encode() if body is not None else None,
                  headers=headers)
        r = c.getresponse()
        b = r.read()
        c.close()
        return r.status, b

    # notes
    def test_get_note_empty(self):
        s, b = self._get("/api/notes/1.2.3.4")
        self.assertEqual(s, 200)
        d = json.loads(b)
        self.assertIn("note", d)

    def test_post_note_and_retrieve(self):
        self._post("/api/notes/8.8.8.8", {"note": "test note"})
        s, b = self._get("/api/notes/8.8.8.8")
        self.assertEqual(s, 200)
        d = json.loads(b)
        self.assertEqual(d["note"], "test note")

    def test_note_missing_ip_400(self):
        s, _ = self._get("/api/notes/")
        self.assertEqual(s, 400)

    # export
    def test_export_connections_json(self):
        s, b = self._get("/api/export/connections")
        self.assertEqual(s, 200)
        d = json.loads(b)
        self.assertIsInstance(d, list)

    def test_export_connections_csv(self):
        s, b = self._get("/api/export/connections?format=csv")
        self.assertEqual(s, 200)

    def test_export_threats_json(self):
        s, b = self._get("/api/export/threats")
        self.assertEqual(s, 200)
        self.assertIsInstance(json.loads(b), list)

    # reports
    def test_reports_list(self):
        s, b = self._get("/api/reports")
        self.assertEqual(s, 200)
        self.assertIsInstance(json.loads(b), list)

    def test_report_not_found_404(self):
        s, _ = self._get("/api/reports/1900-01-01")
        self.assertEqual(s, 404)

    # db stats
    def test_db_stats_endpoint(self):
        s, b = self._get("/api/db/stats")
        self.assertEqual(s, 200)
        d = json.loads(b)
        self.assertIn("table_counts", d)
        self.assertIn("db_size_bytes", d)

    # geo status
    def test_geo_status_endpoint(self):
        s, b = self._get("/api/geo/status")
        self.assertEqual(s, 200)
        d = json.loads(b)
        self.assertIn("source", d)


if __name__ == "__main__":
    unittest.main()
