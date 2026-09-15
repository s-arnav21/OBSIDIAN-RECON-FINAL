"""Tests for the recon → exploit automatic handoff service."""
from __future__ import annotations

import unittest
from unittest import mock

from app.db.repository import PersistenceRepository
from app.models.finding import Finding, ValidationStatus
from app.services.agent_handoff import auto_handoff_completed_scan, handoff_session_name
from tests.db_utils import make_test_session_factory


def make_finding(**overrides) -> Finding:
    values = {
        "finding_id": "finding-handoff-1",
        "scan_id": "scan-handoff-1",
        "asset_id": "asset-handoff-1",
        "target": "http://127.0.0.1:8090",
        "host": "127.0.0.1",
        "port": 8090,
        "protocol": "http",
        "endpoint": "/items",
        "source": "handoff_test",
        "template_id": "handoff-test-template",
        "validator_id": "generic-http-sqli",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "http_method": "GET",
        "parameter_name": "id",
        "parameter_location": "query",
        "validation_status": ValidationStatus.CONFIRMED,
        "validation_confidence": 0.9,
    }
    values.update(overrides)
    return Finding(**values)


class AutoHandoffServiceTests(unittest.TestCase):

    def setUp(self):
        self.engine, factory = make_test_session_factory()
        self.session = factory()
        self.repository = PersistenceRepository(self.session)

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    # ------------------------------------------------------------------ helpers

    def _seed_scan(
        self,
        scan_id: str = "scan-handoff-1",
        asset_id: str = "asset-handoff-1",
        findings: list[Finding] | None = None,
    ) -> None:
        self.repository.create_scan(
            scan_id=scan_id,
            target_url="http://127.0.0.1:8090",
            authorized=True,
            status="completed",
        )
        self.repository.persist_asset(
            scan_id=scan_id,
            asset_id=asset_id,
            hostname="127.0.0.1",
            base_url="http://127.0.0.1:8090",
        )
        for f in findings or []:
            self.repository.persist_finding(f)
        self.session.commit()

    # -------------------------------------------------------------------- tests

    def test_missing_scan_reports_skipped(self):
        report = auto_handoff_completed_scan(
            self.session, scan_id="does-not-exist", authorized=True,
        )
        self.assertEqual(report["status"], "skipped")
        self.assertEqual(report["reason"], "scan_not_found")
        self.assertIsNone(report["session_id"])

    def test_no_eligible_findings_skips_without_session(self):
        self._seed_scan(
            findings=[make_finding(validation_status=ValidationStatus.DETECTED)],
        )
        report = auto_handoff_completed_scan(
            self.session, scan_id="scan-handoff-1", authorized=True,
        )
        self.assertEqual(report["status"], "skipped")
        self.assertEqual(report["reason"], "no_eligible_findings")
        self.assertEqual(
            self.repository.list_exploit_sessions(scan_id="scan-handoff-1"), [],
        )

    def test_llm_not_configured_creates_session_skips_agent(self):
        self._seed_scan(findings=[make_finding()])

        with mock.patch(
            "app.services.agent_handoff._load_llm_client", return_value=None,
        ):
            report = auto_handoff_completed_scan(
                self.session, scan_id="scan-handoff-1", authorized=True,
            )

        self.assertEqual(report["status"], "skipped")
        self.assertEqual(report["reason"], "llm_not_configured")
        sessions = self.repository.list_exploit_sessions(scan_id="scan-handoff-1")
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].session_name, handoff_session_name("scan-handoff-1"))
        self.assertEqual(sessions[0].status, "pending")
        self.assertTrue(sessions[0].id.startswith("auto-"))
        self.session.commit()

    def test_second_call_is_idempotent(self):
        self._seed_scan(findings=[make_finding()])

        with mock.patch(
            "app.services.agent_handoff._load_llm_client", return_value=None,
        ):
            first = auto_handoff_completed_scan(
                self.session, scan_id="scan-handoff-1", authorized=True,
            )
            second = auto_handoff_completed_scan(
                self.session, scan_id="scan-handoff-1", authorized=True,
            )

        self.assertEqual(first["status"], "skipped")
        self.assertEqual(first["reason"], "llm_not_configured")
        self.assertEqual(second["status"], "skipped")
        self.assertEqual(second["reason"], "session_exists")
        self.assertEqual(second["session_id"], first["session_id"])
        self.assertEqual(
            len(self.repository.list_exploit_sessions(scan_id="scan-handoff-1")), 1,
        )
        self.session.commit()


if __name__ == "__main__":
    unittest.main()
