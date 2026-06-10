import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
import alerts
import db


def _setup_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    p = patch("db.DB_PATH", Path(tmp.name))
    p.start()
    db.init_db()
    return tmp, p


class TestLoadRulesFromFile(unittest.TestCase):
    def setUp(self):
        self.tmp, self.p = _setup_db()
        alerts._seen_ips.clear()
        alerts._seen_procs.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_load_rules_from_file_inserts_rule(self):
        rules_data = [{"rule_type": "new_ip", "condition": {}, "action": {"type": "desktop"}}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(rules_data, f)
            rules_path = f.name
        try:
            alerts.load_rules_from_file(rules_path)
            stored = db.get_alert_rules()
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]["rule_type"], "new_ip")
        finally:
            os.unlink(rules_path)

    def test_load_rules_nonexistent_path_does_not_raise(self):
        # Should not raise even with a missing file
        alerts.load_rules_from_file("/nonexistent/path/rules.json")


class TestEvaluateNewIp(unittest.TestCase):
    def setUp(self):
        self.tmp, self.p = _setup_db()
        alerts._seen_ips.clear()
        alerts._seen_procs.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_new_ip_rule_fires_once(self):
        db.create_alert_rule("new_ip", condition="{}", action='{"type":"desktop"}')
        conns = [{"ip": "1.2.3.4", "country": "US", "countryCode": "US", "process": "curl"}]
        alerts.evaluate(conns)
        events = db.get_alert_events()
        self.assertEqual(len(events), 1)

    def test_new_ip_rule_does_not_fire_again_for_same_ip(self):
        db.create_alert_rule("new_ip", condition="{}", action='{"type":"desktop"}')
        conns = [{"ip": "1.2.3.4", "country": "US", "countryCode": "US", "process": "curl"}]
        alerts.evaluate(conns)
        alerts.evaluate(conns)
        events = db.get_alert_events()
        # Should only have fired once
        self.assertEqual(len(events), 1)


class TestEvaluateCountry(unittest.TestCase):
    def setUp(self):
        self.tmp, self.p = _setup_db()
        alerts._seen_ips.clear()
        alerts._seen_procs.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_country_rule_fires_for_matching_country(self):
        db.create_alert_rule("country", condition='{"code":"CN"}', action='{"type":"desktop"}')
        conns = [{"ip": "1.2.3.4", "country": "China", "countryCode": "CN", "process": "curl"}]
        alerts.evaluate(conns)
        events = db.get_alert_events()
        self.assertEqual(len(events), 1)

    def test_country_rule_does_not_fire_for_other_country(self):
        db.create_alert_rule("country", condition='{"code":"CN"}', action='{"type":"desktop"}')
        conns = [{"ip": "1.2.3.4", "country": "US", "countryCode": "US", "process": "curl"}]
        alerts.evaluate(conns)
        events = db.get_alert_events()
        self.assertEqual(len(events), 0)


class TestEvaluateThreatScore(unittest.TestCase):
    def setUp(self):
        self.tmp, self.p = _setup_db()
        alerts._seen_ips.clear()
        alerts._seen_procs.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_threat_score_rule_fires_above_threshold(self):
        db.create_alert_rule("threat_score", condition='{"min_score":75}', action='{"type":"desktop"}')
        conns = [{"ip": "1.2.3.4", "country": "US", "countryCode": "US",
                  "process": "curl", "abuse_score": 90}]
        alerts.evaluate(conns)
        events = db.get_alert_events()
        self.assertEqual(len(events), 1)

    def test_threat_score_rule_does_not_fire_below_threshold(self):
        db.create_alert_rule("threat_score", condition='{"min_score":75}', action='{"type":"desktop"}')
        conns = [{"ip": "1.2.3.4", "country": "US", "countryCode": "US",
                  "process": "curl", "abuse_score": 50}]
        alerts.evaluate(conns)
        events = db.get_alert_events()
        self.assertEqual(len(events), 0)


class TestEvaluateDisabledRule(unittest.TestCase):
    def setUp(self):
        self.tmp, self.p = _setup_db()
        alerts._seen_ips.clear()
        alerts._seen_procs.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_disabled_rule_does_not_fire(self):
        rid = db.create_alert_rule("new_ip", condition="{}", action='{"type":"desktop"}')
        db.update_alert_rule(rid, enabled=0)
        conns = [{"ip": "1.2.3.4", "country": "US", "countryCode": "US", "process": "curl"}]
        alerts.evaluate(conns)
        events = db.get_alert_events()
        self.assertEqual(len(events), 0)


class TestFireWebhook(unittest.TestCase):
    def setUp(self):
        self.tmp, self.p = _setup_db()
        alerts._seen_ips.clear()
        alerts._seen_procs.clear()

    def tearDown(self):
        self.p.stop()
        os.unlink(self.tmp.name)

    def test_fire_webhook_calls_urlopen(self):
        rule = {
            "id": 1,
            "rule_type": "new_ip",
            "action": '{"type":"webhook","url":"https://example.com/hook"}',
        }
        conn = {"ip": "1.2.3.4", "country": "US", "process": "curl"}
        mock_urlopen = MagicMock()
        with patch("urllib.request.urlopen", mock_urlopen):
            alerts._fire(rule, conn)
        mock_urlopen.assert_called_once()


if __name__ == "__main__":
    unittest.main()
