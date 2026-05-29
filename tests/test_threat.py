import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

sys.path.insert(0, str(Path(__file__).parent.parent))
import threat


def _mock_response(payload: dict):
    body = json.dumps(payload).encode()
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestIsEnabled(unittest.TestCase):
    def test_disabled_without_key(self):
        env = {k: v for k, v in os.environ.items() if k != "ABUSEIPDB_KEY"}
        with patch.dict(os.environ, env, clear=True):
            self.assertFalse(threat.is_enabled())

    def test_enabled_with_key(self):
        with patch.dict(os.environ, {"ABUSEIPDB_KEY": "abc123"}):
            self.assertTrue(threat.is_enabled())

    def test_enabled_with_any_nonempty_key(self):
        with patch.dict(os.environ, {"ABUSEIPDB_KEY": "x"}):
            self.assertTrue(threat.is_enabled())


class TestCheckIP(unittest.TestCase):
    def test_parses_score_and_reports(self):
        payload = {"data": {"abuseConfidenceScore": 42, "totalReports": 7}}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            r = threat._check_ip("1.2.3.4", "key")
        self.assertEqual(r["abuse_score"], 42)
        self.assertEqual(r["reports"], 7)

    def test_clean_ip_score_zero(self):
        payload = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            r = threat._check_ip("8.8.8.8", "key")
        self.assertEqual(r["abuse_score"], 0)
        self.assertEqual(r["reports"], 0)

    def test_high_score_malicious(self):
        payload = {"data": {"abuseConfidenceScore": 100, "totalReports": 999}}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            r = threat._check_ip("1.2.3.4", "key")
        self.assertEqual(r["abuse_score"], 100)

    def test_returns_none_on_url_error(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            r = threat._check_ip("1.2.3.4", "key")
        self.assertIsNone(r)

    def test_returns_none_on_403(self):
        err = urllib.error.HTTPError(None, 403, "Forbidden", {}, None)
        with patch("urllib.request.urlopen", side_effect=err):
            r = threat._check_ip("1.2.3.4", "key")
        self.assertIsNone(r)

    def test_returns_none_on_429_and_backs_off(self):
        err = urllib.error.HTTPError(None, 429, "Too Many Requests", {}, None)
        with patch("urllib.request.urlopen", side_effect=err), \
             patch("time.sleep") as mock_sleep:
            r = threat._check_ip("1.2.3.4", "key")
        self.assertIsNone(r)
        mock_sleep.assert_called_once_with(60)

    def test_missing_data_key_defaults_to_zero(self):
        # API returns unexpected shape
        payload = {"data": {}}
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            r = threat._check_ip("1.2.3.4", "key")
        self.assertEqual(r["abuse_score"], 0)
        self.assertEqual(r["reports"], 0)
