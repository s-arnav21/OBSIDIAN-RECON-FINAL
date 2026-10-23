"""mitmproxy flow -> EvidenceStore conversion (duck-typed, no dependency)."""
from __future__ import annotations

import unittest

from app.automation.evidence import EvidenceStore
from app.automation import mitm_capture


class _Headers(dict):
    pass


class _Request:
    method = "POST"
    pretty_url = "http://h/login"
    headers = _Headers({"Content-Type": "application/x-www-form-urlencoded"})

    def get_text(self):
        return "user=admin&pass=x"


class _Response:
    status_code = 200
    headers = _Headers({"Content-Type": "text/html"})

    def get_text(self):
        return "<html>ok</html>"


class _Flow:
    def __init__(self, request=_Request(), response=_Response()):
        self.request = request
        self.response = response


class FlowConversionTests(unittest.TestCase):
    def test_flow_to_entry(self):
        entry = mitm_capture.flow_to_entry(_Flow(), finding_id="f1")
        self.assertEqual(entry.method, "POST")
        self.assertEqual(entry.url, "http://h/login")
        self.assertEqual(entry.status_code, 200)
        self.assertEqual(entry.request_body, "user=admin&pass=x")
        self.assertEqual(entry.response_body, "<html>ok</html>")
        self.assertEqual(entry.meta["source"], "mitmproxy")

    def test_flow_without_request_is_skipped(self):
        self.assertIsNone(mitm_capture.flow_to_entry(object()))

    def test_capture_from_flows_counts_and_stores(self):
        store = EvidenceStore()
        count = mitm_capture.capture_from_flows([_Flow(), _Flow()], store)
        self.assertEqual(count, 2)
        self.assertEqual(len(store), 2)

    def test_addon_records_responses(self):
        store = EvidenceStore()
        addon = mitm_capture.EvidenceCaptureAddon(store, finding_id="f")
        addon.response(_Flow())
        self.assertEqual(len(addon.captured), 1)
        self.assertEqual(len(store.for_finding("f")), 1)

    def test_malformed_flow_fails_soft(self):
        class _BadRequest:
            method = "GET"
            pretty_url = "http://h/"

            @property
            def headers(self):
                raise RuntimeError("bad")

        class _BadFlow:
            request = _BadRequest()
            response = None

        self.assertIsNone(mitm_capture.flow_to_entry(_BadFlow()))


if __name__ == "__main__":
    unittest.main()
