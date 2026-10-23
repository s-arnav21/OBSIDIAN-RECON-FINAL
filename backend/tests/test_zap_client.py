"""OWASP ZAP REST adapter (fail-soft, gated on configuration)."""
from __future__ import annotations

import unittest
from unittest import mock

from app.automation import zap_client


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _FakeHttp:
    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params))
        return _FakeResponse(self.payloads.pop(0))


class ZapClientTests(unittest.TestCase):
    def test_version_and_spider(self):
        http = _FakeHttp([{"version": "2.14.0"}, {"scan": "7"}])
        client = zap_client.ZapClient("http://zap:8080", http_session=http)
        self.assertEqual(client.version(), "2.14.0")
        self.assertEqual(client.spider("http://h/"), 7)

    def test_status_is_int_or_none(self):
        http = _FakeHttp([{"status": "100"}, {"status": "not-a-number"}])
        client = zap_client.ZapClient("http://zap:8080", http_session=http)
        self.assertEqual(client.spider_status(1), 100)
        self.assertIsNone(client.spider_status(1))

    def test_alerts_returns_list(self):
        http = _FakeHttp([{"alerts": [{"name": "XSS"}]}])
        client = zap_client.ZapClient("http://zap:8080", http_session=http)
        self.assertEqual(client.alerts("http://h/"), [{"name": "XSS"}])

    def test_transport_error_is_fail_soft(self):
        http = mock.Mock()
        http.get.side_effect = OSError("no route")
        client = zap_client.ZapClient("http://zap:8080", http_session=http)
        self.assertIsNone(client.version())
        self.assertEqual(client.alerts("http://h/"), [])

    def test_api_key_is_sent(self):
        http = _FakeHttp([{"version": "1"}])
        client = zap_client.ZapClient("http://zap:8080", api_key="secret", http_session=http)
        client.version()
        self.assertEqual(http.calls[0][1]["apikey"], "secret")

    def test_wait_returns_true_when_complete(self):
        client = zap_client.ZapClient("http://zap:8080", http_session=_FakeHttp([]))
        self.assertTrue(client.wait(lambda sid: 100, 1, timeout=1, interval=1))

    def test_wait_times_out_when_not_complete(self):
        client = zap_client.ZapClient("http://zap:8080", http_session=_FakeHttp([]))
        self.assertFalse(client.wait(lambda sid: 10, 1, timeout=1, interval=1))


class ConfigurationTests(unittest.TestCase):
    def test_configured_false_without_base_url(self):
        class _S:
            ZAP_BASE_URL = ""

        self.assertFalse(zap_client.configured(_S()))
        self.assertIsNone(zap_client.from_settings(_S()))

    def test_from_settings_builds_client(self):
        class _S:
            ZAP_BASE_URL = "http://zap:8080"
            ZAP_API_KEY = "k"
            ZAP_TIMEOUT = 5

        client = zap_client.from_settings(_S())
        self.assertEqual(client.base_url, "http://zap:8080")


if __name__ == "__main__":
    unittest.main()
