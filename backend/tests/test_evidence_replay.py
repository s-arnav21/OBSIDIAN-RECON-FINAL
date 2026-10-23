"""Evidence capture/replay (VulnClaw traffic/store + traffic/replay pattern)."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from app.automation.evidence import EvidenceEntry, EvidenceStore


class _FakeResponse:
    status_code = 200
    headers = {"Content-Type": "text/plain"}
    text = "ok-body"


class RecordTests(unittest.TestCase):
    def test_record_exchange_from_response_object(self):
        store = EvidenceStore()
        entry = store.record_exchange(
            "get",
            "http://h/items",
            request_headers={"A": "b"},
            response=_FakeResponse(),
            finding_id="f1",
        )
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.status_code, 200)
        self.assertEqual(entry.response_body, "ok-body")
        self.assertEqual(len(store.for_finding("f1")), 1)

    def test_store_is_bounded(self):
        store = EvidenceStore(max_entries=3)
        for i in range(6):
            store.record_exchange("GET", f"http://h/{i}")
        self.assertEqual(len(store), 3)
        self.assertEqual(store.recent(1)[0].url, "http://h/5")

    def test_bodies_and_headers_are_truncated(self):
        store = EvidenceStore()
        entry = store.record_exchange(
            "POST",
            "http://h/x",
            request_body="z" * 300_000,
            request_headers={"X": "y" * 10_000},
        )
        self.assertLessEqual(len(entry.request_body), 200_000)
        self.assertLessEqual(len(entry.request_headers["X"]), 4_000)


class ReplayTests(unittest.TestCase):
    def test_replay_applies_overrides_and_records(self):
        store = EvidenceStore()
        original = store.record_exchange("GET", "http://h/items", request_headers={"A": "b"})
        session = mock.Mock()
        session.request.return_value = _FakeResponse()
        replayed = store.replay(
            original, overrides={"method": "post", "headers": {"C": "d"}}, http_session=session
        )
        self.assertEqual(replayed.method, "POST")
        self.assertEqual(replayed.request_headers["C"], "d")
        self.assertEqual(replayed.meta["replay_of"], original.entry_id)
        self.assertEqual(len(store), 2)

    def test_replay_transport_error_is_recorded_not_raised(self):
        store = EvidenceStore()
        original = store.record_exchange("GET", "http://h/items")
        session = mock.Mock()
        session.request.side_effect = OSError("down")
        replayed = store.replay(original, http_session=session)
        self.assertIn("OSError", replayed.meta["error"])


class PersistenceTests(unittest.TestCase):
    def test_round_trip_json(self):
        store = EvidenceStore()
        store.record_exchange("GET", "http://h/a", response=_FakeResponse(), finding_id="f")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "evidence.json")
            self.assertTrue(store.save(path))
            loaded = EvidenceStore.load(path)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded.all()[0].url, "http://h/a")
        self.assertEqual(json.loads(store.to_json())[0]["finding_id"], "f")

    def test_load_missing_file_is_empty(self):
        self.assertEqual(len(EvidenceStore.load("/nonexistent/evidence.json")), 0)

    def test_from_dict_ignores_unknown_keys(self):
        entry = EvidenceEntry.from_dict({"method": "GET", "url": "http://h", "bogus": 1})
        self.assertEqual(entry.method, "GET")


if __name__ == "__main__":
    unittest.main()
