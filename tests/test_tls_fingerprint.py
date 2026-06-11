"""
Tests for tls_fingerprint.py — unit tests that don't require real network.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, mock_open

sys.path.insert(0, str(Path(__file__).parent.parent))
import tls_fingerprint


class TestHexConversions(unittest.TestCase):
    def test_hex_to_ip4_google_dns(self):
        # 8.8.8.8 in little-endian hex = 08080808
        result = tls_fingerprint._hex_to_ip4("08080808")
        self.assertEqual(result, "8.8.8.8")

    def test_hex_to_ip4_loopback(self):
        result = tls_fingerprint._hex_to_ip4("0100007F")
        self.assertEqual(result, "127.0.0.1")

    def test_hex_port(self):
        self.assertEqual(tls_fingerprint._hex_port("01BB"), 443)
        self.assertEqual(tls_fingerprint._hex_port("0050"), 80)


class TestGetTlsInfo(unittest.TestCase):
    def test_returns_required_keys(self):
        info = tls_fingerprint.get_tls_info("8.8.8.8", "443")
        self.assertIn("ip", info)
        self.assertIn("port", info)
        self.assertIn("tls", info)

    def test_correct_ip_and_port(self):
        info = tls_fingerprint.get_tls_info("1.2.3.4", "443")
        self.assertEqual(info["ip"], "1.2.3.4")
        self.assertEqual(info["port"], 443)
        self.assertTrue(info["tls"])

    def test_tls_false_for_non_443(self):
        info = tls_fingerprint.get_tls_info("1.2.3.4", "80")
        self.assertEqual(info["port"], 80)
        self.assertFalse(info["tls"])

    def test_note_present_when_not_connected(self):
        # No real connection exists in test env, so note should be present
        info = tls_fingerprint.get_tls_info("240.0.0.1", "443")
        # Either note is present or connected is True (very unlikely in test env)
        if not info.get("connected"):
            self.assertIn("note", info)

    def test_connected_key_present(self):
        info = tls_fingerprint.get_tls_info("8.8.8.8", "443")
        self.assertIn("connected", info)
        self.assertIsInstance(info["connected"], bool)

    def test_proc_unavailable_degrades_gracefully(self):
        """When /proc/net/tcp is unreadable, function should not raise."""
        with patch("builtins.open", side_effect=OSError("no proc")):
            info = tls_fingerprint.get_tls_info("8.8.8.8", "443")
        self.assertEqual(info["ip"], "8.8.8.8")
        self.assertFalse(info["connected"])

    def test_ss_unavailable_degrades_gracefully(self):
        """When ss is not installed, function should not raise."""
        import subprocess
        with patch("subprocess.check_output", side_effect=FileNotFoundError):
            info = tls_fingerprint.get_tls_info("8.8.8.8", "443")
        self.assertEqual(info["ip"], "8.8.8.8")

    def test_established_proc_detected(self):
        """Simulate /proc/net/tcp with an established entry for 8.8.8.8:443."""
        # 8.8.8.8 little-endian hex = 08080808, port 443 = 01BB
        proc_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue "
            "tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:C4E2 08080808:01BB 01 00000000:00000000 "
            "00:00000000 00000000  1000        0 12345 1 0000000000000000 "
            "20 4 24 10 -1\n"
        )
        with patch("builtins.open", mock_open(read_data=proc_content)):
            result = tls_fingerprint._is_established_proc("8.8.8.8", 443)
        self.assertTrue(result)

    def test_established_proc_not_matched(self):
        """Simulate /proc/net/tcp with no matching entry."""
        proc_content = (
            "  sl  local_address rem_address   st\n"
            "   0: 00000000:C4E2 01010101:01BB 01 00000000:00000000\n"
        )
        with patch("builtins.open", mock_open(read_data=proc_content)):
            result = tls_fingerprint._is_established_proc("8.8.8.8", 443)
        self.assertFalse(result)


class TestSsTlsInfo(unittest.TestCase):
    def test_empty_output_returns_empty_dict(self):
        with patch("subprocess.check_output", return_value=""):
            result = tls_fingerprint._ss_tls_info("8.8.8.8", 443)
        self.assertEqual(result, {})

    def test_tls13_version_detected(self):
        fake_output = "ESTAB 0 0 192.168.1.1:50000 8.8.8.8:443\n  TLSv1.3 rto:200 wscale:7:7\n"
        with patch("subprocess.check_output", return_value=fake_output):
            result = tls_fingerprint._ss_tls_info("8.8.8.8", 443)
        self.assertEqual(result.get("tls_version"), "TLS1.3")

    def test_tls12_version_detected(self):
        fake_output = "ESTAB 0 0 192.168.1.1:50000 8.8.8.8:443\n  TLSv1.2 rto:200\n"
        with patch("subprocess.check_output", return_value=fake_output):
            result = tls_fingerprint._ss_tls_info("8.8.8.8", 443)
        self.assertEqual(result.get("tls_version"), "TLS1.2")

    def test_rto_field_extracted(self):
        fake_output = "ESTAB 0 0 192.168.1.1:50000 8.8.8.8:443\n  rto:201 wscale:7:7 rtt:1.5/0.75\n"
        with patch("subprocess.check_output", return_value=fake_output):
            result = tls_fingerprint._ss_tls_info("8.8.8.8", 443)
        self.assertIn("rto", result)
