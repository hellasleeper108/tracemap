"""Unit tests for pcap.py — does not require tcpdump."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import pcap


class TestSafeIp(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(pcap._safe_ip("1.2.3.4"))

    def test_valid_ipv6(self):
        self.assertTrue(pcap._safe_ip("2001:db8::1"))

    def test_rejects_shell_chars(self):
        self.assertFalse(pcap._safe_ip("1.2.3.4; rm -rf /"))
        self.assertFalse(pcap._safe_ip("$(evil)"))
        self.assertFalse(pcap._safe_ip(""))

    def test_rejects_dotdot(self):
        self.assertFalse(pcap._safe_ip("../etc/passwd"))


class TestIsAvailable(unittest.TestCase):
    def test_returns_bool(self):
        self.assertIsInstance(pcap.is_available(), bool)


class TestStartCapture(unittest.TestCase):
    def test_invalid_ip(self):
        result = pcap.start_capture("not_an_ip!!!", 5)
        self.assertEqual(result["status"], "invalid_ip")
        self.assertIsNone(result["file"])

    def test_unavailable_when_no_tcpdump(self):
        with patch.object(pcap, "is_available", return_value=False):
            result = pcap.start_capture("1.2.3.4", 1)
        self.assertEqual(result["status"], "unavailable")


class TestStatus(unittest.TestCase):
    def test_returns_valid_string(self):
        self.assertIn(pcap.status("1.2.3.4"), ("running", "idle", "unavailable"))


class TestListCaptures(unittest.TestCase):
    def test_empty_dir(self):
        with patch.object(pcap, "PCAP_DIR", Path("/nonexistent/__tracemap_test__")):
            self.assertEqual(pcap.list_captures("1.2.3.4"), [])

    def test_finds_pcap_files(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "1.2.3.4_20260101T000000Z.pcap").write_bytes(b"PCAP")
            with patch.object(pcap, "PCAP_DIR", p):
                result = pcap.list_captures("1.2.3.4")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["file"], "1.2.3.4_20260101T000000Z.pcap")
        self.assertEqual(result[0]["size"], 4)

    def test_invalid_ip(self):
        self.assertEqual(pcap.list_captures("bad!!!"), [])


class TestGetCapturePath(unittest.TestCase):
    def test_traversal_blocked(self):
        self.assertIsNone(pcap.get_capture_path("../etc/passwd"))
        self.assertIsNone(pcap.get_capture_path("foo/bar.pcap"))

    def test_no_extension(self):
        self.assertIsNone(pcap.get_capture_path("noext"))

    def test_missing_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with patch.object(pcap, "PCAP_DIR", Path(d)):
                self.assertIsNone(pcap.get_capture_path("missing.pcap"))

    def test_existing_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            f = p / "1.2.3.4_20260101T000000Z.pcap"
            f.write_bytes(b"")
            with patch.object(pcap, "PCAP_DIR", p):
                result = pcap.get_capture_path(f.name)
        self.assertEqual(result, f)


if __name__ == "__main__":
    unittest.main()
