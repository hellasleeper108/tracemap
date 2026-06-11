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


class TestGeoOfflineMode(unittest.TestCase):
    """Tests for set_geoip_paths, is_offline, and _lookup_offline."""

    def setUp(self):
        # Ensure offline readers are cleared before each test
        geo._geoip_db  = None
        geo._geoip_asn = None

    def tearDown(self):
        geo._geoip_db  = None
        geo._geoip_asn = None

    def test_is_offline_false_by_default(self):
        self.assertFalse(geo.is_offline())

    def test_set_geoip_paths_noop_when_both_none(self):
        geo.set_geoip_paths(None, None)
        self.assertFalse(geo.is_offline())

    def test_set_geoip_paths_warns_when_maxminddb_missing(self):
        """When maxminddb is not importable, a warning is logged and offline stays False."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "maxminddb":
                raise ImportError("no module named maxminddb")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            geo.set_geoip_paths("/fake/city.mmdb", None)
        self.assertFalse(geo.is_offline())

    def test_set_geoip_paths_opens_readers_when_maxminddb_available(self):
        """When maxminddb is importable and paths are valid, readers are set."""
        fake_reader = MagicMock()
        fake_maxminddb = MagicMock()
        fake_maxminddb.open_database.return_value = fake_reader

        import sys
        sys.modules["maxminddb"] = fake_maxminddb
        try:
            geo.set_geoip_paths("/fake/city.mmdb", "/fake/asn.mmdb")
        finally:
            del sys.modules["maxminddb"]

        self.assertIsNotNone(geo._geoip_db)
        self.assertIsNotNone(geo._geoip_asn)
        self.assertTrue(geo.is_offline())

    def test_lookup_offline_returns_none_when_not_configured(self):
        self.assertIsNone(geo._lookup_offline("8.8.8.8"))

    def test_lookup_offline_returns_data_from_city_reader(self):
        """_lookup_offline builds a response dict from the MaxMind city record."""
        fake_reader = MagicMock()
        fake_reader.get.return_value = {
            "country":  {"iso_code": "DE", "names": {"en": "Germany"}},
            "city":     {"names": {"en": "Berlin"}},
            "location": {"latitude": 52.5, "longitude": 13.4},
        }
        geo._geoip_db = fake_reader
        geo._geoip_asn = None

        result = geo._lookup_offline("1.2.3.4")
        self.assertIsNotNone(result)
        self.assertEqual(result["countryCode"], "DE")
        self.assertEqual(result["city"], "Berlin")
        self.assertAlmostEqual(result["lat"], 52.5)
        self.assertAlmostEqual(result["lon"], 13.4)
        self.assertEqual(result["query"], "1.2.3.4")
        self.assertEqual(result["status"], "success")

    def test_lookup_offline_returns_none_on_miss(self):
        """_lookup_offline returns None when the reader returns None (IP not in DB)."""
        fake_reader = MagicMock()
        fake_reader.get.return_value = None
        geo._geoip_db = fake_reader
        geo._geoip_asn = None

        result = geo._lookup_offline("1.2.3.4")
        self.assertIsNone(result)

    def test_geolocate_uses_offline_reader_on_cache_miss(self):
        """geolocate() should call _lookup_offline for IPs not in cache."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        offline_data = {
            "query": "1.2.3.4", "status": "success",
            "country": "Germany", "countryCode": "DE",
            "city": "Berlin", "lat": 52.5, "lon": 13.4, "org": "ACME", "isp": "ACME",
        }
        with patch("db.DB_PATH", Path(tmp.name)):
            db.init_db()
            with patch("geo._lookup_offline", return_value=offline_data) as mock_offline, \
                 patch("urllib.request.urlopen") as mock_url:
                result = geo.geolocate(["1.2.3.4"])
            mock_offline.assert_called_once_with("1.2.3.4")
            mock_url.assert_not_called()
            self.assertEqual(result["1.2.3.4"]["city"], "Berlin")
        os.unlink(tmp.name)

    def test_geolocate_falls_back_to_online_on_offline_miss(self):
        """geolocate() should fall back to ip-api.com when offline reader returns None."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        with patch("db.DB_PATH", Path(tmp.name)):
            db.init_db()
            with patch("geo._lookup_offline", return_value=None), \
                 patch("urllib.request.urlopen",
                        return_value=_mock_response([GEO_ROW])) as mock_url:
                result = geo.geolocate(["1.2.3.4"])
            mock_url.assert_called_once()
            self.assertIn("1.2.3.4", result)
        os.unlink(tmp.name)
