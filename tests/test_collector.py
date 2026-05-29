import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from collector import _parse_peer, _extract_process, _is_public


class TestParsePeer(unittest.TestCase):
    # ── IPv4 ──────────────────────────────────────────────────────────────────

    def test_ipv4_standard(self):
        ip, port = _parse_peer("1.2.3.4:443")
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(port, "443")

    def test_ipv4_ephemeral_port(self):
        ip, port = _parse_peer("203.0.113.1:54321")
        self.assertEqual(ip, "203.0.113.1")
        self.assertEqual(port, "54321")

    def test_ipv4_port_80(self):
        ip, port = _parse_peer("192.0.2.1:80")
        self.assertEqual(port, "80")

    # ── IPv6 ─────────────────────────────────────────────────────────────────

    def test_ipv6_bracketed(self):
        ip, port = _parse_peer("[2001:db8::1]:80")
        self.assertEqual(ip, "2001:db8::1")
        self.assertEqual(port, "80")

    def test_ipv6_bracketed_full(self):
        ip, port = _parse_peer("[2606:4700:4700::1111]:443")
        self.assertEqual(ip, "2606:4700:4700::1111")
        self.assertEqual(port, "443")

    def test_ipv6_mapped_ipv4(self):
        ip, port = _parse_peer("[::ffff:1.2.3.4]:443")
        self.assertEqual(ip, "::ffff:1.2.3.4")
        self.assertEqual(port, "443")

    # ── Edge cases ────────────────────────────────────────────────────────────

    def test_invalid_bracket_no_crash(self):
        # malformed — must not raise
        try:
            _parse_peer("[bad")
        except Exception as e:
            self.fail(f"_parse_peer raised unexpectedly: {e}")

    def test_empty_string_no_crash(self):
        try:
            _parse_peer("")
        except Exception as e:
            self.fail(f"_parse_peer raised unexpectedly: {e}")


class TestExtractProcess(unittest.TestCase):
    def test_simple_process(self):
        self.assertEqual(_extract_process('users:(("chrome",pid=1234,fd=5))'), "chrome")

    def test_hyphenated_process(self):
        self.assertEqual(_extract_process('users:(("brave-browser",pid=42,fd=10))'), "brave-browser")

    def test_underscore_process(self):
        self.assertEqual(_extract_process('users:(("my_app",pid=99,fd=3))'), "my_app")

    def test_empty_field(self):
        self.assertEqual(_extract_process(""), "")

    def test_no_users_prefix(self):
        self.assertEqual(_extract_process("some other text"), "")

    def test_multiple_connections_returns_first(self):
        field = 'users:(("app1",pid=1,fd=1),("app2",pid=2,fd=2))'
        self.assertEqual(_extract_process(field), "app1")


class TestIsPublic(unittest.TestCase):
    # ── Should be public ──────────────────────────────────────────────────────

    def test_google_dns(self):
        self.assertTrue(_is_public("8.8.8.8"))

    def test_cloudflare_dns(self):
        self.assertTrue(_is_public("1.1.1.1"))

    def test_public_class_a(self):
        self.assertTrue(_is_public("104.16.0.1"))  # Cloudflare CDN

    def test_ipv6_public(self):
        self.assertTrue(_is_public("2001:4860:4860::8888"))

    # ── Should NOT be public ──────────────────────────────────────────────────

    def test_private_10(self):
        self.assertFalse(_is_public("10.0.0.1"))

    def test_private_10_wide(self):
        self.assertFalse(_is_public("10.255.255.255"))

    def test_private_172_16(self):
        self.assertFalse(_is_public("172.16.0.1"))

    def test_private_172_31(self):
        self.assertFalse(_is_public("172.31.255.255"))

    def test_private_192_168(self):
        self.assertFalse(_is_public("192.168.1.100"))

    def test_loopback(self):
        self.assertFalse(_is_public("127.0.0.1"))

    def test_loopback_other(self):
        self.assertFalse(_is_public("127.255.0.1"))

    def test_link_local(self):
        self.assertFalse(_is_public("169.254.1.1"))

    def test_multicast(self):
        self.assertFalse(_is_public("224.0.0.1"))

    def test_multicast_high(self):
        self.assertFalse(_is_public("239.255.255.255"))

    def test_ipv6_loopback(self):
        self.assertFalse(_is_public("::1"))

    def test_ipv6_link_local(self):
        self.assertFalse(_is_public("fe80::1"))

    def test_invalid_string(self):
        self.assertFalse(_is_public("not.an.ip.address"))

    def test_empty_string(self):
        self.assertFalse(_is_public(""))
