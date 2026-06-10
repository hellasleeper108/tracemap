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
        self.assertIn("dns_cache", tables)
        self.assertIn("reputation_cache", tables)
        self.assertIn("threat_sources", tables)
        self.assertIn("alert_rules", tables)
        self.assertIn("alert_events", tables)
        self.assertIn("blocked_ips", tables)

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


class TestDnsCache(unittest.TestCase):
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
        db.set_hostname("1.2.3.4", "example.com")
        self.assertEqual(db.get_hostname("1.2.3.4"), "example.com")

    def test_empty_hostname_stored(self):
        db.set_hostname("1.2.3.4", "")
        self.assertEqual(db.get_hostname("1.2.3.4"), "")

    def test_missing_returns_none(self):
        self.assertIsNone(db.get_hostname("99.99.99.99"))

    def test_stale_returns_none(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "INSERT INTO dns_cache (ip, hostname, resolved_at) VALUES (?,?,?)",
            ("1.2.3.4", "example.com", int(time.time()) - 90000)
        )
        conn.commit()
        conn.close()
        self.assertIsNone(db.get_hostname("1.2.3.4"))

    def test_upsert_overwrites(self):
        db.set_hostname("1.2.3.4", "old.example.com")
        db.set_hostname("1.2.3.4", "new.example.com")
        self.assertEqual(db.get_hostname("1.2.3.4"), "new.example.com")


class TestReputationCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_bulk_set_and_get_ips(self):
        db.bulk_set_reputation("tor_exit", ["1.2.3.4", "5.6.7.8"])
        ips = db.get_reputation_ips("tor_exit")
        self.assertIn("1.2.3.4", ips)
        self.assertIn("5.6.7.8", ips)

    def test_get_ips_empty_source(self):
        self.assertEqual(db.get_reputation_ips("tor_exit"), [])

    def test_fetched_at_returned(self):
        before = int(time.time())
        db.bulk_set_reputation("tor_exit", ["1.2.3.4"])
        ts = db.get_reputation_fetched_at("tor_exit")
        self.assertIsNotNone(ts)
        self.assertGreaterEqual(ts, before)

    def test_fetched_at_missing_source_returns_none(self):
        self.assertIsNone(db.get_reputation_fetched_at("unknown_source"))

    def test_is_flagged_true(self):
        db.bulk_set_reputation("tor_exit", ["1.2.3.4"])
        self.assertTrue(db.is_reputation_flagged("tor_exit", "1.2.3.4"))

    def test_is_flagged_false_unknown(self):
        self.assertFalse(db.is_reputation_flagged("tor_exit", "9.9.9.9"))

    def test_bulk_set_replaces_old_ips(self):
        db.bulk_set_reputation("tor_exit", ["1.2.3.4"])
        db.bulk_set_reputation("tor_exit", ["5.6.7.8"])
        ips = db.get_reputation_ips("tor_exit")
        self.assertNotIn("1.2.3.4", ips)
        self.assertIn("5.6.7.8", ips)


class TestThreatSources(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_set_and_get_source(self):
        db.set_threat_source("1.2.3.4", "virustotal", 45, {"mal": 3, "sus": 2})
        sources = db.get_threat_sources("1.2.3.4")
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["source"], "virustotal")
        self.assertEqual(sources[0]["score"], 45)

    def test_raw_is_stored(self):
        raw = {"malicious": 5, "suspicious": 1}
        db.set_threat_source("1.2.3.4", "virustotal", 60, raw)
        sources = db.get_threat_sources("1.2.3.4")
        import json
        stored_raw = json.loads(sources[0]["raw"])
        self.assertEqual(stored_raw["malicious"], 5)

    def test_multiple_sources(self):
        db.set_threat_source("1.2.3.4", "virustotal", 40, {})
        db.set_threat_source("1.2.3.4", "shodan", 20, {})
        sources = db.get_threat_sources("1.2.3.4")
        source_names = {s["source"] for s in sources}
        self.assertIn("virustotal", source_names)
        self.assertIn("shodan", source_names)

    def test_get_sources_unknown_ip(self):
        sources = db.get_threat_sources("9.9.9.9")
        self.assertEqual(sources, [])

    def test_needs_source_check_no_existing(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
            ("1.2.3.4", "443", "", "", int(time.time()))
        )
        conn.commit()
        conn.close()
        ips = db.get_ips_needing_source_check("virustotal", ttl=3600)
        self.assertIn("1.2.3.4", ips)

    def test_needs_source_check_fresh_excluded(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
            ("1.2.3.4", "443", "", "", int(time.time()))
        )
        conn.commit()
        conn.close()
        db.set_threat_source("1.2.3.4", "virustotal", 0, {})
        ips = db.get_ips_needing_source_check("virustotal", ttl=3600)
        self.assertNotIn("1.2.3.4", ips)


class TestAlertRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_create_returns_id(self):
        rid = db.create_alert_rule("new_ip")
        self.assertIsInstance(rid, int)
        self.assertGreater(rid, 0)

    def test_get_rule_roundtrip(self):
        rid = db.create_alert_rule("country", '{"code":"CN"}', '{"type":"desktop"}')
        rule = db.get_alert_rule(rid)
        self.assertIsNotNone(rule)
        self.assertEqual(rule["rule_type"], "country")
        self.assertEqual(rule["condition"], '{"code":"CN"}')
        self.assertEqual(rule["enabled"], 1)

    def test_get_all_rules(self):
        db.create_alert_rule("new_ip")
        db.create_alert_rule("country", '{"code":"US"}')
        rules = db.get_alert_rules(enabled_only=False)
        self.assertEqual(len(rules), 2)

    def test_get_enabled_only(self):
        rid = db.create_alert_rule("new_ip")
        db.create_alert_rule("country", '{"code":"US"}')
        db.update_alert_rule(rid, enabled=0)
        rules = db.get_alert_rules(enabled_only=True)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["rule_type"], "country")

    def test_update_enabled(self):
        rid = db.create_alert_rule("new_ip")
        db.update_alert_rule(rid, enabled=0)
        rule = db.get_alert_rule(rid)
        self.assertEqual(rule["enabled"], 0)

    def test_update_condition(self):
        rid = db.create_alert_rule("threat_score", '{"min_score":50}')
        db.update_alert_rule(rid, condition='{"min_score":90}')
        rule = db.get_alert_rule(rid)
        self.assertEqual(rule["condition"], '{"min_score":90}')

    def test_delete_rule(self):
        rid = db.create_alert_rule("new_ip")
        db.delete_alert_rule(rid)
        self.assertIsNone(db.get_alert_rule(rid))

    def test_get_missing_rule_returns_none(self):
        self.assertIsNone(db.get_alert_rule(9999))

    def test_update_noop_no_fields(self):
        rid = db.create_alert_rule("new_ip")
        db.update_alert_rule(rid)  # no-op; must not raise


class TestAlertEvents(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()
        self.rid = db.create_alert_rule("new_ip")

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_create_returns_id(self):
        eid = db.create_alert_event(self.rid, "new_ip", "1.2.3.4", "test msg")
        self.assertIsInstance(eid, int)
        self.assertGreater(eid, 0)

    def test_get_events(self):
        db.create_alert_event(self.rid, "new_ip", "1.2.3.4", "msg1")
        db.create_alert_event(self.rid, "new_ip", "5.6.7.8", "msg2")
        events = db.get_alert_events()
        self.assertEqual(len(events), 2)

    def test_events_ordered_newest_first(self):
        db.create_alert_event(self.rid, "new_ip", "1.2.3.4", "first")
        time.sleep(0.01)
        db.create_alert_event(self.rid, "new_ip", "2.2.2.2", "second")
        events = db.get_alert_events()
        self.assertEqual(events[0]["ip"], "2.2.2.2")

    def test_unread_count(self):
        db.create_alert_event(self.rid, "new_ip", "1.2.3.4", "m")
        db.create_alert_event(self.rid, "new_ip", "2.2.2.2", "m")
        self.assertEqual(db.get_unread_alert_count(), 2)

    def test_pop_pending_returns_unsent(self):
        db.create_alert_event(self.rid, "new_ip", "1.2.3.4", "pending")
        pending = db.pop_pending_alerts()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["ip"], "1.2.3.4")

    def test_pop_pending_marks_sent(self):
        db.create_alert_event(self.rid, "new_ip", "1.2.3.4", "pending")
        db.pop_pending_alerts()
        pending_again = db.pop_pending_alerts()
        self.assertEqual(len(pending_again), 0)

    def test_mark_all_read(self):
        db.create_alert_event(self.rid, "new_ip", "1.2.3.4", "m")
        db.create_alert_event(self.rid, "new_ip", "2.2.2.2", "m")
        db.mark_alerts_read(None)
        self.assertEqual(db.get_unread_alert_count(), 0)

    def test_mark_specific_read(self):
        eid = db.create_alert_event(self.rid, "new_ip", "1.2.3.4", "m")
        db.create_alert_event(self.rid, "new_ip", "2.2.2.2", "m")
        db.mark_alerts_read([eid])
        self.assertEqual(db.get_unread_alert_count(), 1)


class TestTimeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_returns_list_of_dicts(self):
        tl = db.get_timeline(window_hours=2)
        self.assertIsInstance(tl, list)
        for bucket in tl:
            self.assertIn("hour_ts", bucket)
            self.assertIn("count", bucket)

    def test_fills_zero_buckets(self):
        tl = db.get_timeline(window_hours=3)
        self.assertGreaterEqual(len(tl), 3)

    def test_count_reflects_logged_conns(self):
        now = int(time.time())
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
            ("1.2.3.4", "443", "", "", now)
        )
        conn.commit()
        conn.close()
        tl = db.get_timeline(window_hours=2)
        total = sum(b["count"] for b in tl)
        self.assertGreater(total, 0)


class TestConnectionsAt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_returns_connections_in_window(self):
        ts = int(time.time())
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
            ("1.2.3.4", "443", "", "curl", ts)
        )
        conn.commit()
        conn.close()
        results = db.get_connections_at(ts, window=300)
        ips = [r["ip"] for r in results]
        self.assertIn("1.2.3.4", ips)

    def test_excludes_outside_window(self):
        ts = int(time.time())
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
            ("1.2.3.4", "443", "", "curl", ts - 1000)
        )
        conn.commit()
        conn.close()
        results = db.get_connections_at(ts, window=300)
        self.assertEqual(len(results), 0)

    def test_result_has_expected_fields(self):
        ts = int(time.time())
        db.set_geo("1.2.3.4", {"country": "US", "countryCode": "US", "city": "NYC",
                                "lat": 40.7, "lon": -74.0, "org": "Acme", "isp": "Acme"})
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "INSERT INTO connections_log (ip, port, local_port, process, seen_at) VALUES (?,?,?,?,?)",
            ("1.2.3.4", "443", "", "curl", ts)
        )
        conn.commit()
        conn.close()
        results = db.get_connections_at(ts, window=300)
        self.assertEqual(len(results), 1)
        row = results[0]
        self.assertEqual(row["ip"], "1.2.3.4")
        self.assertEqual(row["port"], "443")
        self.assertEqual(row["country"], "US")

    def test_resolved_at_set(self):
        before = int(time.time())
        db.set_hostname("1.2.3.4", "example.com")
        conn = sqlite3.connect(self.tmp.name)
        row = conn.execute("SELECT resolved_at FROM dns_cache WHERE ip = ?", ("1.2.3.4",)).fetchone()
        conn.close()
        self.assertGreaterEqual(row[0], before)


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


class TestBlockedIps(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_add_and_is_blocked(self):
        db.add_blocked_ip("8.8.8.8")
        self.assertTrue(db.is_blocked_ip("8.8.8.8"))

    def test_not_blocked_initially(self):
        self.assertFalse(db.is_blocked_ip("1.1.1.1"))

    def test_remove_blocked_ip(self):
        db.add_blocked_ip("8.8.8.8")
        db.remove_blocked_ip("8.8.8.8")
        self.assertFalse(db.is_blocked_ip("8.8.8.8"))

    def test_remove_nonexistent_no_error(self):
        db.remove_blocked_ip("1.2.3.4")  # should not raise

    def test_get_blocked_ips_empty(self):
        self.assertEqual(db.get_blocked_ips(), [])

    def test_get_blocked_ips_returns_entries(self):
        db.add_blocked_ip("1.1.1.1")
        db.add_blocked_ip("2.2.2.2")
        entries = db.get_blocked_ips()
        ips = {e["ip"] for e in entries}
        self.assertIn("1.1.1.1", ips)
        self.assertIn("2.2.2.2", ips)

    def test_get_blocked_ips_has_blocked_at(self):
        db.add_blocked_ip("8.8.8.8")
        entries = db.get_blocked_ips()
        self.assertIn("blocked_at", entries[0])
        self.assertGreater(entries[0]["blocked_at"], 0)

    def test_upsert_does_not_duplicate(self):
        db.add_blocked_ip("8.8.8.8")
        db.add_blocked_ip("8.8.8.8")
        self.assertEqual(len(db.get_blocked_ips()), 1)
