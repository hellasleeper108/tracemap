import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import db
from collector import _parse_peer, _extract_process, _is_public, _resolve_hostname, resolve_hostnames


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


class TestResolveHostname(unittest.TestCase):
    def test_getfqdn_returns_ip_means_empty(self):
        with patch("socket.getfqdn", return_value="8.8.8.8"):
            _, hostname = _resolve_hostname("8.8.8.8")
        self.assertEqual(hostname, "")

    def test_getfqdn_returns_name(self):
        with patch("socket.getfqdn", return_value="dns.google"):
            _, hostname = _resolve_hostname("8.8.8.8")
        self.assertEqual(hostname, "dns.google")

    def test_getfqdn_returns_ip_as_name(self):
        ip, hostname = _resolve_hostname("8.8.8.8")
        self.assertEqual(ip, "8.8.8.8")

    def test_exception_returns_empty_string(self):
        with patch("socket.getfqdn", side_effect=OSError("timeout")):
            _, hostname = _resolve_hostname("1.2.3.4")
        self.assertEqual(hostname, "")


class TestResolveHostnames(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_empty_list_returns_empty_dict(self):
        self.assertEqual(resolve_hostnames([]), {})

    def test_uses_db_cache(self):
        db.set_hostname("1.2.3.4", "cached.example.com")
        with patch("socket.getfqdn") as mock_fqdn:
            result = resolve_hostnames(["1.2.3.4"])
            mock_fqdn.assert_not_called()
        self.assertEqual(result["1.2.3.4"], "cached.example.com")

    def test_resolves_uncached_ip(self):
        with patch("socket.getfqdn", return_value="example.com"):
            result = resolve_hostnames(["1.2.3.4"])
        self.assertEqual(result["1.2.3.4"], "example.com")

    def test_caches_resolved_hostname(self):
        with patch("socket.getfqdn", return_value="example.com"):
            resolve_hostnames(["1.2.3.4"])
        self.assertEqual(db.get_hostname("1.2.3.4"), "example.com")

    def test_dns_failure_returns_empty_string(self):
        with patch("socket.getfqdn", side_effect=OSError("Network unreachable")):
            result = resolve_hostnames(["1.2.3.4"])
        self.assertEqual(result.get("1.2.3.4"), "")

    def test_dns_failure_caches_empty_string(self):
        with patch("socket.getfqdn", side_effect=OSError("timeout")):
            resolve_hostnames(["1.2.3.4"])
        self.assertEqual(db.get_hostname("1.2.3.4"), "")


class TestGetStateHostname(unittest.TestCase):
    def test_get_state_includes_hostname(self):
        import collector
        original = collector._connections
        try:
            collector._connections = [{
                "ip": "1.2.3.4", "port": "443",
                "hostname": "example.com", "process": "test",
            }]
            state = collector.get_state()
            self.assertGreater(len(state["connections"]), 0)
            self.assertEqual(state["connections"][0]["hostname"], "example.com")
        finally:
            collector._connections = original


# ── Bandwidth helpers ─────────────────────────────────────────────────────────

from collector import _parse_bw_info, _compute_bw, _extract_pid


class TestParseBwInfo(unittest.TestCase):
    def test_bytes_received_parsed(self):
        line = "\t bytes_received:12345 bytes_sent:0 send_queue:0 cwnd:10"
        recv, sent = _parse_bw_info(line)
        self.assertEqual(recv, 12345)

    def test_bytes_sent_parsed(self):
        line = "\t bytes_received:100 bytes_sent:500"
        recv, sent = _parse_bw_info(line)
        self.assertEqual(sent, 500)

    def test_bytes_acked_fallback(self):
        line = "\t bytes_received:100 bytes_acked:300"
        recv, sent = _parse_bw_info(line)
        self.assertEqual(sent, 300)

    def test_empty_line_returns_zeros(self):
        recv, sent = _parse_bw_info("")
        self.assertEqual(recv, 0)
        self.assertEqual(sent, 0)

    def test_bytes_sent_preferred_over_acked(self):
        line = "\t bytes_received:0 bytes_sent:200 bytes_acked:100"
        recv, sent = _parse_bw_info(line)
        self.assertEqual(sent, 200)


class TestComputeBw(unittest.TestCase):
    def setUp(self):
        import collector
        collector._bw_state.clear()

    def tearDown(self):
        import collector
        collector._bw_state.clear()

    def test_first_call_returns_zero_bps(self):
        recv_bps, send_bps = _compute_bw(("1.2.3.4", "443", "5000"), 1000, 500, 1000.0)
        self.assertEqual(recv_bps, 0.0)
        self.assertEqual(send_bps, 0.0)

    def test_second_call_computes_delta(self):
        key = ("1.2.3.4", "443", "5000")
        _compute_bw(key, 0, 0, 1000.0)
        recv_bps, send_bps = _compute_bw(key, 10000, 5000, 1010.0)
        self.assertAlmostEqual(recv_bps, 1000.0, places=1)
        self.assertAlmostEqual(send_bps, 500.0, places=1)

    def test_negative_bytes_recv_returns_zero(self):
        key = ("1.2.3.4", "443", "5000")
        _compute_bw(key, 1000, 0, 1000.0)
        # bytes_recv went backwards (shouldn't happen normally)
        recv_bps, send_bps = _compute_bw(key, 500, 0, 1010.0)
        self.assertEqual(recv_bps, 0.0)


class TestExtractPid(unittest.TestCase):
    def test_extracts_pid(self):
        field = 'users:(("chrome",pid=1234,fd=5))'
        self.assertEqual(_extract_pid(field), 1234)

    def test_returns_none_when_no_pid(self):
        self.assertIsNone(_extract_pid(""))

    def test_returns_none_for_unrelated_text(self):
        self.assertIsNone(_extract_pid("some text without pid"))


# ── Docker helpers ────────────────────────────────────────────────────────────

from collector import _get_container_id, _get_container_name, _resolve_container


class TestGetContainerId(unittest.TestCase):
    def test_finds_container_id(self):
        cgroup_content = "12:cpu:/docker/abc123def456789012345678901234567890abcdef12345678\n"
        mock_open = unittest.mock.mock_open(read_data=cgroup_content)
        with patch("builtins.open", mock_open):
            cid = _get_container_id(1234)
        self.assertEqual(cid, "abc123def456")

    def test_returns_none_when_no_docker(self):
        cgroup_content = "12:cpu:/system.slice/sshd.service\n"
        mock_open = unittest.mock.mock_open(read_data=cgroup_content)
        with patch("builtins.open", mock_open):
            cid = _get_container_id(1234)
        self.assertIsNone(cid)

    def test_returns_none_on_oserror(self):
        with patch("builtins.open", side_effect=OSError):
            cid = _get_container_id(9999)
        self.assertIsNone(cid)


class TestResolveContainer(unittest.TestCase):
    def test_returns_empty_when_pid_none(self):
        cid, cname = _resolve_container(None)
        self.assertEqual(cid, "")
        self.assertEqual(cname, "")

    def test_returns_empty_when_no_container_id(self):
        with patch("collector._get_container_id", return_value=None):
            cid, cname = _resolve_container(1234)
        self.assertEqual(cid, "")
        self.assertEqual(cname, "")

    def test_returns_name_from_docker_socket(self):
        with patch("collector._get_container_id", return_value="abc123def456"), \
             patch("collector._get_container_name", return_value="my-container"):
            cid, cname = _resolve_container(1234)
        self.assertEqual(cid, "abc123def456")
        self.assertEqual(cname, "my-container")

    def test_handles_missing_container_name(self):
        with patch("collector._get_container_id", return_value="abc123def456"), \
             patch("collector._get_container_name", return_value=None):
            cid, cname = _resolve_container(1234)
        self.assertEqual(cid, "abc123def456")
        self.assertEqual(cname, "")
