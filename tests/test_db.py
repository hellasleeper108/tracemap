import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import db


class TestDBSetup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_tables_created(self):
        conn = sqlite3.connect(self.tmp.name)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertIn("geo_cache", tables)
        self.assertIn("connections_log", tables)
        self.assertIn("threat_cache", tables)
        self.assertIn("traceroutes", tables)

    def test_init_is_idempotent(self):
        db.init_db()  # second call must not raise


class TestGeoCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    GEO = {"country": "US", "countryCode": "US", "city": "NYC",
           "lat": 40.7, "lon": -74.0, "org": "Acme Corp", "isp": "Acme ISP"}

    def test_roundtrip(self):
        db.set_geo("1.2.3.4", self.GEO)
        r = db.get_geo("1.2.3.4")
        self.assertIsNotNone(r)
        self.assertEqual(r["city"], "NYC")
        self.assertEqual(r["countryCode"], "US")
        self.assertAlmostEqual(r["lat"], 40.7)

    def test_missing_returns_none(self):
        self.assertIsNone(db.get_geo("99.99.99.99"))

    def test_upsert_overwrites(self):
        db.set_geo("1.2.3.4", self.GEO)
        updated = {**self.GEO, "city": "Boston"}
        db.set_geo("1.2.3.4", updated)
        self.assertEqual(db.get_geo("1.2.3.4")["city"], "Boston")

    def test_fetched_at_set(self):
        before = int(time.time())
        db.set_geo("1.2.3.4", self.GEO)
        r = db.get_geo("1.2.3.4")
        self.assertGreaterEqual(r["fetched_at"], before)


class TestConnectionsLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    CONNS = [
        {"ip": "1.2.3.4", "port": "443", "local_port": "11111", "process": "chrome"},
        {"ip": "5.6.7.8", "port": "80",  "local_port": "22222", "process": "curl"},
    ]

    def test_log_and_retrieve(self):
        db.log_connections(self.CONNS)
        h = db.get_history("1.2.3.4")
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["ip"], "1.2.3.4")
        self.assertEqual(h[0]["port"], "443")
        self.assertEqual(h[0]["process"], "chrome")

    def test_empty_log_is_noop(self):
        db.log_connections([])  # must not raise

    def test_history_ordered_newest_first(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.execute("INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
                     ("1.2.3.4", "443", "", "chrome", 1000))
        conn.execute("INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
                     ("1.2.3.4", "443", "", "chrome", 2000))
        conn.commit()
        conn.close()
        h = db.get_history("1.2.3.4")
        self.assertEqual(h[0]["seen_at"], 2000)
        self.assertEqual(h[1]["seen_at"], 1000)

    def test_history_limit_respected(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.executemany(
            "INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
            [("1.2.3.4", "443", "", "chrome", i) for i in range(600)])
        conn.commit()
        conn.close()
        h = db.get_history("1.2.3.4", limit=100)
        self.assertEqual(len(h), 100)

    def test_get_first_seen(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.execute("INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
                     ("1.2.3.4", "443", "", "", 5000))
        conn.execute("INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
                     ("1.2.3.4", "443", "", "", 3000))
        conn.commit()
        conn.close()
        self.assertEqual(db.get_first_seen("1.2.3.4"), 3000)

    def test_get_first_seen_missing(self):
        self.assertIsNone(db.get_first_seen("99.99.99.99"))


class TestThreatCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_roundtrip(self):
        db.set_threat("1.2.3.4", {"abuse_score": 85, "reports": 12})
        t = db.get_threat("1.2.3.4")
        self.assertIsNotNone(t)
        self.assertEqual(t["abuse_score"], 85)
        self.assertEqual(t["reports"], 12)

    def test_missing_returns_none(self):
        self.assertIsNone(db.get_threat("99.99.99.99"))

    def test_upsert_overwrites(self):
        db.set_threat("1.2.3.4", {"abuse_score": 10, "reports": 1})
        db.set_threat("1.2.3.4", {"abuse_score": 99, "reports": 50})
        self.assertEqual(db.get_threat("1.2.3.4")["abuse_score"], 99)

    def test_needs_check_no_cache(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.execute("INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
                     ("1.2.3.4", "443", "", "", int(time.time())))
        conn.commit()
        conn.close()
        ips = db.get_ips_needing_threat_check(ttl=3600)
        self.assertIn("1.2.3.4", ips)

    def test_needs_check_fresh_cache_excluded(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.execute("INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
                     ("1.2.3.4", "443", "", "", int(time.time())))
        conn.commit()
        conn.close()
        db.set_threat("1.2.3.4", {"abuse_score": 0, "reports": 0})
        ips = db.get_ips_needing_threat_check(ttl=3600)
        self.assertNotIn("1.2.3.4", ips)

    def test_needs_check_stale_cache_included(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.execute("INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
                     ("1.2.3.4", "443", "", "", int(time.time())))
        conn.execute("INSERT INTO threat_cache (ip, abuse_score, reports, checked_at) VALUES (?,?,?,?)",
                     ("1.2.3.4", 0, 0, int(time.time()) - 7200))
        conn.commit()
        conn.close()
        ips = db.get_ips_needing_threat_check(ttl=3600)
        self.assertIn("1.2.3.4", ips)

    def test_limit_respected(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.executemany(
            "INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
            [(f"1.1.1.{i}", "443", "", "", int(time.time())) for i in range(20)])
        conn.commit()
        conn.close()
        ips = db.get_ips_needing_threat_check(ttl=3600, limit=5)
        self.assertLessEqual(len(ips), 5)


class TestTracerouteStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    HOPS = [
        {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.2,  "lat": None, "lon": None, "city": None},
        {"hop": 2, "ip": "8.8.8.8",     "rtt_ms": 10.5, "lat": 37.4, "lon": -122.0, "city": "Mountain View"},
        {"hop": 3, "ip": None,           "rtt_ms": None, "lat": None, "lon": None,   "city": None},
    ]

    def test_roundtrip(self):
        db.store_traceroute("8.8.8.8", self.HOPS)
        r = db.get_traceroute("8.8.8.8")
        self.assertIsNotNone(r)
        self.assertEqual(r["ip"], "8.8.8.8")
        self.assertEqual(len(r["hops"]), 3)
        self.assertIsNotNone(r["ran_at"])

    def test_hops_preserved(self):
        db.store_traceroute("8.8.8.8", self.HOPS)
        hops = db.get_traceroute("8.8.8.8")["hops"]
        self.assertEqual(hops[1]["ip"], "8.8.8.8")
        self.assertAlmostEqual(hops[1]["rtt_ms"], 10.5)
        self.assertIsNone(hops[2]["ip"])

    def test_missing_returns_none(self):
        self.assertIsNone(db.get_traceroute("99.99.99.99"))

    def test_upsert_replaces_old_result(self):
        db.store_traceroute("8.8.8.8", self.HOPS)
        db.store_traceroute("8.8.8.8", [{"hop": 1, "ip": "1.1.1.1", "rtt_ms": 5.0}])
        r = db.get_traceroute("8.8.8.8")
        self.assertEqual(len(r["hops"]), 1)
        self.assertEqual(r["hops"][0]["ip"], "1.1.1.1")
