import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
import db
from traceroute import _parse_output, start, get_result


SAMPLE_OUTPUT = """\
traceroute to 8.8.8.8 (8.8.8.8), 20 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.123 ms  0.987 ms
 2  10.0.0.1  5.678 ms  5.432 ms  5.210 ms
 3  * * *
 4  203.0.113.5  10.111 ms  9.876 ms  10.543 ms
20  8.8.8.8  11.234 ms  11.100 ms  11.050 ms
"""


class TestParseOutput(unittest.TestCase):
    def test_hop_count(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertEqual(len(hops), 5)

    def test_first_hop_number(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertEqual(hops[0]["hop"], 1)

    def test_first_hop_ip(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertEqual(hops[0]["ip"], "192.168.1.1")

    def test_first_hop_rtt(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertAlmostEqual(hops[0]["rtt_ms"], 1.234)

    def test_star_hop_ip_is_none(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertIsNone(hops[2]["ip"])

    def test_star_hop_rtt_is_none(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertIsNone(hops[2]["rtt_ms"])

    def test_star_hop_number_preserved(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertEqual(hops[2]["hop"], 3)

    def test_last_hop_ip(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertEqual(hops[-1]["ip"], "8.8.8.8")

    def test_last_hop_number(self):
        hops = _parse_output(SAMPLE_OUTPUT)
        self.assertEqual(hops[-1]["hop"], 20)

    def test_empty_output(self):
        hops = _parse_output("traceroute to 8.8.8.8, 20 hops\n")
        self.assertEqual(hops, [])

    def test_all_stars(self):
        output = "traceroute to 1.1.1.1 (1.1.1.1)\n" + \
                 "\n".join(f" {i}  * * *" for i in range(1, 6))
        hops = _parse_output(output)
        self.assertEqual(len(hops), 5)
        for h in hops:
            self.assertIsNone(h["ip"])

    def test_single_hop(self):
        output = "traceroute to 8.8.8.8\n 1  8.8.8.8  0.500 ms\n"
        hops = _parse_output(output)
        self.assertEqual(len(hops), 1)
        self.assertEqual(hops[0]["ip"], "8.8.8.8")

    def test_rtt_from_first_measurement(self):
        # Multiple RTT columns — we take the first one
        output = "traceroute to 1.1.1.1\n 1  1.1.1.1  5.000 ms  6.000 ms  7.000 ms\n"
        hops = _parse_output(output)
        self.assertAlmostEqual(hops[0]["rtt_ms"], 5.0)


class TestStartAndGetResult(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()
        # Reset _running set between tests
        import traceroute as tr_mod
        tr_mod._running.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_get_result_not_found(self):
        r = get_result("1.2.3.4")
        self.assertEqual(r.get("status"), "not_found")

    def test_start_returns_running(self):
        with patch("traceroute._trace_and_store"):  # don't actually trace
            status = start("1.2.3.4")
        self.assertEqual(status, "running")

    def test_start_already_running(self):
        import traceroute as tr_mod
        tr_mod._running.add("1.2.3.4")
        status = start("1.2.3.4")
        self.assertEqual(status, "already_running")
        tr_mod._running.discard("1.2.3.4")

    def test_start_returns_cached_for_fresh_result(self):
        hops = [{"hop": 1, "ip": "8.8.8.8", "rtt_ms": 5.0}]
        db.store_traceroute("1.2.3.4", hops)
        status = start("1.2.3.4")
        self.assertEqual(status, "cached")

    def test_start_reruns_for_stale_result(self):
        hops = [{"hop": 1, "ip": "8.8.8.8", "rtt_ms": 5.0}]
        import sqlite3
        conn = sqlite3.connect(self.tmp.name)
        import json
        conn.execute("INSERT INTO traceroutes (target_ip, ran_at, hops) VALUES (?,?,?)",
                     ("1.2.3.4", int(time.time()) - 7200, json.dumps(hops)))
        conn.commit()
        conn.close()

        import traceroute as tr_mod
        with patch.object(tr_mod, "CACHE_TTL", 3600):
            with patch("traceroute._trace_and_store"):
                status = start("1.2.3.4")
        self.assertEqual(status, "running")

    def test_get_result_running_status(self):
        import traceroute as tr_mod
        tr_mod._running.add("5.5.5.5")
        r = get_result("5.5.5.5")
        self.assertEqual(r.get("status"), "running")
        tr_mod._running.discard("5.5.5.5")

    def test_get_result_returns_cached_hops(self):
        hops = [{"hop": 1, "ip": "1.1.1.1", "rtt_ms": 2.5}]
        db.store_traceroute("1.2.3.4", hops)
        r = get_result("1.2.3.4")
        self.assertIn("hops", r)
        self.assertEqual(r["hops"][0]["ip"], "1.1.1.1")
