import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import urllib.error

sys.path.insert(0, str(Path(__file__).parent.parent))
import reputation
import db


class TestIsVpn(unittest.TestCase):
    def test_known_vpn_false(self):
        self.assertFalse(reputation.is_vpn("AS9009 M247 Ltd"))

    def test_nordvpn_true(self):
        self.assertTrue(reputation.is_vpn("NordVPN"))

    def test_nordvpn_lowercase_true(self):
        self.assertTrue(reputation.is_vpn("nordvpn ltd"))

    def test_protonvpn_true(self):
        self.assertTrue(reputation.is_vpn("ProtonVPN GmbH"))

    def test_empty_string_false(self):
        self.assertFalse(reputation.is_vpn(""))

    def test_none_returns_false_no_error(self):
        # should not raise, return False
        result = reputation.is_vpn(None)
        self.assertFalse(result)


class TestIsTor(unittest.TestCase):
    def setUp(self):
        reputation._exits.clear()

    def test_unknown_ip_is_not_tor(self):
        self.assertFalse(reputation.is_tor("1.2.3.4"))

    def test_added_ip_is_tor(self):
        reputation._exits.add("1.2.3.4")
        self.assertTrue(reputation.is_tor("1.2.3.4"))

    def test_cleared_ip_is_not_tor(self):
        reputation._exits.add("1.2.3.4")
        reputation._exits.clear()
        self.assertFalse(reputation.is_tor("1.2.3.4"))


class TestFetch(unittest.TestCase):
    def _make_urlopen_response(self, body_bytes):
        resp = MagicMock()
        resp.read.return_value = body_bytes
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_fetch_returns_list_on_valid_response(self):
        mock_resp = self._make_urlopen_response(b"1.2.3.4\n5.6.7.8\n# comment\n")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = reputation._fetch()
        self.assertIsInstance(result, list)
        self.assertIn("1.2.3.4", result)
        self.assertIn("5.6.7.8", result)
        # Comments should be filtered out
        self.assertNotIn("# comment", result)

    def test_fetch_returns_empty_list_on_url_error(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            result = reputation._fetch()
        self.assertEqual(result, [])


class TestCheckerLoopDBCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()
        reputation._exits.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)
        reputation._exits.clear()

    def test_checker_loop_loads_from_fresh_db_cache(self):
        # Simulate a fresh cache in the DB
        recent_ts = int(time.time()) - 60  # 1 minute old — well within TOR_REFRESH
        with patch("db.get_reputation_fetched_at", return_value=recent_ts), \
             patch("db.get_reputation_ips", return_value=["1.2.3.4"]), \
             patch("time.sleep", side_effect=InterruptedError):
            # checker_loop enters the while True loop after loading cache;
            # InterruptedError from sleep exits it cleanly
            try:
                reputation.checker_loop()
            except InterruptedError:
                pass

        self.assertTrue(reputation.is_tor("1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
