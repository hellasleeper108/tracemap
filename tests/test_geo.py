import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

sys.path.insert(0, str(Path(__file__).parent.parent))
import db
import geo


def _mock_response(payload):
    body = json.dumps(payload).encode()
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


GEO_ROW = {
    "status": "success", "query": "1.2.3.4",
    "country": "US", "countryCode": "US", "city": "Chicago",
    "lat": 41.8, "lon": -87.6, "org": "Acme", "isp": "Acme ISP",
}


class TestGeolocate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_cache_hit_skips_network(self):
        db.set_geo("1.2.3.4", GEO_ROW)
        with patch("urllib.request.urlopen") as mock_url:
            result = geo.geolocate(["1.2.3.4"])
        mock_url.assert_not_called()
        self.assertIn("1.2.3.4", result)

    def test_cache_hit_returns_correct_city(self):
        db.set_geo("1.2.3.4", GEO_ROW)
        result = geo.geolocate(["1.2.3.4"])
        self.assertEqual(result["1.2.3.4"]["city"], "Chicago")

    def test_cache_miss_calls_api(self):
        with patch("urllib.request.urlopen",
                   return_value=_mock_response([GEO_ROW])) as mock_url:
            result = geo.geolocate(["1.2.3.4"])
        mock_url.assert_called_once()
        self.assertIn("1.2.3.4", result)

    def test_cache_miss_stores_result(self):
        with patch("urllib.request.urlopen", return_value=_mock_response([GEO_ROW])):
            geo.geolocate(["1.2.3.4"])
        cached = db.get_geo("1.2.3.4")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["city"], "Chicago")

    def test_failed_status_excluded(self):
        fail_row = {"status": "fail", "query": "1.2.3.4", "message": "reserved range"}
        with patch("urllib.request.urlopen", return_value=_mock_response([fail_row])):
            result = geo.geolocate(["1.2.3.4"])
        self.assertNotIn("1.2.3.4", result)

    def test_empty_list_returns_empty(self):
        with patch("urllib.request.urlopen") as mock_url:
            result = geo.geolocate([])
        mock_url.assert_not_called()
        self.assertEqual(result, {})

    def test_stale_cache_triggers_refetch(self):
        # Insert record with fetched_at older than GEO_TTL
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "INSERT INTO geo_cache (ip, country, countryCode, city, lat, lon, org, isp, fetched_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            ("1.2.3.4", "US", "US", "OldCity", 40.0, -74.0, "Org", "ISP",
             int(time.time()) - geo.GEO_TTL - 1)
        )
        conn.commit()
        conn.close()

        fresh_row = {**GEO_ROW, "city": "FreshCity"}
        with patch("urllib.request.urlopen", return_value=_mock_response([fresh_row])):
            result = geo.geolocate(["1.2.3.4"])
        self.assertEqual(result["1.2.3.4"]["city"], "FreshCity")

    def test_multiple_ips_batched(self):
        rows = [
            {**GEO_ROW, "query": "1.1.1.1", "city": "A"},
            {**GEO_ROW, "query": "2.2.2.2", "city": "B"},
        ]
        with patch("urllib.request.urlopen", return_value=_mock_response(rows)):
            result = geo.geolocate(["1.1.1.1", "2.2.2.2"])
        self.assertIn("1.1.1.1", result)
        self.assertIn("2.2.2.2", result)

    def test_network_error_returns_partial(self):
        db.set_geo("1.1.1.1", GEO_ROW)  # cached
        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.URLError("down")):
            result = geo.geolocate(["1.1.1.1", "2.2.2.2"])
        # Cached IP still returned, uncached one dropped
        self.assertIn("1.1.1.1", result)
        self.assertNotIn("2.2.2.2", result)


class TestGetHostGeo(unittest.TestCase):
    def test_returns_data_on_success(self):
        payload = {"status": "success", "query": "1.2.3.4", "country": "US",
                   "city": "NYC", "lat": 40.7, "lon": -74.0, "org": "ISP"}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            r = geo.get_host_geo()
        self.assertEqual(r["query"], "1.2.3.4")
        self.assertEqual(r["city"], "NYC")

    def test_fallback_on_network_error(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            r = geo.get_host_geo()
        self.assertEqual(r["query"], "unknown")
        self.assertEqual(r["lat"], 0)
        self.assertEqual(r["lon"], 0)

    def test_fallback_on_failed_status(self):
        payload = {"status": "fail"}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            r = geo.get_host_geo()
        self.assertEqual(r["query"], "unknown")
