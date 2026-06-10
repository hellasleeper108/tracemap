import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import agent


class TestAgentAuth(unittest.TestCase):
    def setUp(self):
        agent.set_agent_key(None)

    def tearDown(self):
        agent.set_agent_key(None)

    def test_no_key_always_passes(self):
        self.assertTrue(agent.check_auth(None))
        self.assertTrue(agent.check_auth("anything"))

    def test_key_required_correct(self):
        agent.set_agent_key("secret123")
        self.assertTrue(agent.check_auth("secret123"))

    def test_key_required_wrong(self):
        agent.set_agent_key("secret123")
        self.assertFalse(agent.check_auth("wrong"))
        self.assertFalse(agent.check_auth(None))

    def test_get_agent_key(self):
        agent.set_agent_key("mykey")
        self.assertEqual(agent.get_agent_key(), "mykey")

    def test_set_key_none_clears(self):
        agent.set_agent_key("key")
        agent.set_agent_key(None)
        self.assertTrue(agent.check_auth(None))


class TestHubConfig(unittest.TestCase):
    def setUp(self):
        agent._hub_mode = False
        agent._agents   = []
        agent._agent_states.clear()

    def tearDown(self):
        agent._hub_mode = False
        agent._agents   = []
        agent._agent_states.clear()

    def test_load_hub_config(self):
        cfg = [{"url": "http://host1:9999", "label": "server1"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            fname = f.name
        try:
            agent.load_hub_config(fname)
            self.assertTrue(agent.is_hub())
            self.assertEqual(len(agent._agents), 1)
            self.assertEqual(agent._agents[0]["label"], "server1")
        finally:
            os.unlink(fname)

    def test_is_hub_false_by_default(self):
        self.assertFalse(agent.is_hub())

    def test_get_merged_connections_empty(self):
        self.assertEqual(agent.get_merged_connections(), [])

    def test_get_agent_status_empty(self):
        self.assertEqual(agent.get_agent_status(), [])


class _FakeAgentHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler serving a fixed /api/connections response."""
    def log_message(self, *args): pass

    def do_GET(self):
        body = json.dumps({"connections": [
            {"ip": "1.2.3.4", "port": "443"}
        ]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestHubPolling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("localhost", 19998), _FakeAgentHandler)
        cls.srv_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.srv_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        agent._agent_states.clear()
        agent._hub_mode = False
        agent._agents   = []

    def tearDown(self):
        agent._agent_states.clear()
        agent._hub_mode = False
        agent._agents   = []

    def test_poll_one_success(self):
        cfg = {"url": "http://localhost:19998", "label": "test-agent"}
        agent._poll_one(cfg)
        with agent._lock:
            state = agent._agent_states.get("test-agent")
        self.assertIsNotNone(state)
        self.assertTrue(state["online"])
        conns = state.get("connections", [])
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0]["ip"], "1.2.3.4")
        self.assertEqual(conns[0]["agent_label"], "test-agent")

    def test_poll_one_failure_marks_offline(self):
        cfg = {"url": "http://localhost:19997", "label": "dead-agent"}
        agent._poll_one(cfg)
        with agent._lock:
            state = agent._agent_states.get("dead-agent")
        self.assertIsNotNone(state)
        self.assertFalse(state["online"])
        self.assertEqual(state["connections"], [])

    def test_get_merged_connections(self):
        cfg = {"url": "http://localhost:19998", "label": "merged-agent"}
        agent._poll_one(cfg)
        merged = agent.get_merged_connections()
        self.assertTrue(any(c["ip"] == "1.2.3.4" for c in merged))

    def test_get_agent_status(self):
        cfg = {"url": "http://localhost:19998", "label": "status-agent"}
        agent._poll_one(cfg)
        statuses = agent.get_agent_status()
        found = next((s for s in statuses if s["label"] == "status-agent"), None)
        self.assertIsNotNone(found)
        self.assertTrue(found["online"])
        self.assertEqual(found["conn_count"], 1)
        self.assertGreater(found["last_contact"], 0)


if __name__ == "__main__":
    unittest.main()
