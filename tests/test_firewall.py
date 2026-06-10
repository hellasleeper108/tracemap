import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import db
import firewall


class TestFirewallAvailability(unittest.TestCase):
    def test_unavailable_when_not_root(self):
        with patch("os.geteuid", return_value=1000):
            self.assertFalse(firewall.is_available())

    def test_unavailable_when_iptables_missing(self):
        with patch("os.geteuid", return_value=0), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertFalse(firewall.is_available())

    def test_unavailable_when_iptables_fails(self):
        mock = MagicMock()
        mock.returncode = 1
        with patch("os.geteuid", return_value=0), \
             patch("subprocess.run", return_value=mock):
            self.assertFalse(firewall.is_available())

    def test_available_when_root_and_iptables_ok(self):
        mock = MagicMock()
        mock.returncode = 0
        with patch("os.geteuid", return_value=0), \
             patch("subprocess.run", return_value=mock):
            self.assertTrue(firewall.is_available())


class TestFirewallBlockUnblock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()
        # Reset rate limiter
        firewall._block_times.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def _available(self):
        return patch("firewall.is_available", return_value=True)

    def _ipt_ok(self):
        mock = MagicMock()
        mock.returncode = 0
        return patch("subprocess.run", return_value=mock)

    def test_block_returns_error_when_unavailable(self):
        with patch("firewall.is_available", return_value=False):
            r = firewall.block("1.2.3.4")
            self.assertFalse(r["ok"])
            self.assertIn("unavailable", r["error"])

    def test_block_refuses_private_ip(self):
        with self._available():
            r = firewall.block("192.168.1.1")
            self.assertFalse(r["ok"])
            self.assertIn("private", r["error"])

    def test_block_refuses_loopback(self):
        with self._available():
            r = firewall.block("127.0.0.1")
            self.assertFalse(r["ok"])

    def test_block_success(self):
        with self._available(), self._ipt_ok():
            r = firewall.block("8.8.8.8")
            self.assertTrue(r["ok"])
            self.assertTrue(db.is_blocked_ip("8.8.8.8"))

    def test_block_already_blocked_returns_note(self):
        with self._available(), self._ipt_ok():
            firewall.block("8.8.8.8")
            r2 = firewall.block("8.8.8.8")
            self.assertTrue(r2["ok"])
            self.assertIn("already", r2.get("note", ""))

    def test_unblock_removes_from_db(self):
        with self._available(), self._ipt_ok():
            firewall.block("8.8.8.8")
            self.assertTrue(db.is_blocked_ip("8.8.8.8"))
            firewall.unblock("8.8.8.8")
            self.assertFalse(db.is_blocked_ip("8.8.8.8"))

    def test_unblock_error_when_unavailable(self):
        with patch("firewall.is_available", return_value=False):
            r = firewall.unblock("8.8.8.8")
            self.assertFalse(r["ok"])

    def test_get_blocked_returns_list(self):
        with self._available(), self._ipt_ok():
            firewall.block("1.1.1.1")
            firewall.block("2.2.2.2")
            blocked = firewall.get_blocked()
            ips = {b["ip"] for b in blocked}
            self.assertIn("1.1.1.1", ips)
            self.assertIn("2.2.2.2", ips)

    def test_is_blocked_helper(self):
        with self._available(), self._ipt_ok():
            self.assertFalse(firewall.is_blocked("8.8.8.8"))
            firewall.block("8.8.8.8")
            self.assertTrue(firewall.is_blocked("8.8.8.8"))


class TestFirewallRateLimit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.p = patch("db.DB_PATH", Path(self.tmp.name))
        self.p.start()
        db.init_db()
        firewall._block_times.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)
        firewall._block_times.clear()

    def test_rate_limit_triggers_after_max(self):
        mock = MagicMock()
        mock.returncode = 0
        with patch("firewall.is_available", return_value=True), \
             patch("subprocess.run", return_value=mock):
            # Fill up to the limit
            for i in range(firewall._RATE_LIMIT):
                ip = f"10.0.{i}.1"
                # bypass private check via patching _is_safe
                with patch("firewall._is_safe", return_value=True):
                    result = firewall.block(ip)
                    self.assertTrue(result["ok"], f"block {i} failed: {result}")
            # Next one should be rate-limited
            with patch("firewall._is_safe", return_value=True):
                r = firewall.block("10.0.99.1")
            self.assertFalse(r["ok"])
            self.assertIn("rate limit", r["error"])

    def test_rate_window_resets(self):
        now = time.time()
        # Inject old timestamps outside the window
        firewall._block_times[:] = [now - firewall._RATE_WINDOW - 1] * firewall._RATE_LIMIT
        self.assertTrue(firewall._rate_ok())


if __name__ == "__main__":
    unittest.main()
