"""Persistence coverage for the controlled test-harness API boundary."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.test_harness import get_test_harness_pipeline
from app.db.models import (
    EvidenceORM,
    FindingORM,
    MitreMappingORM,
    ScanORM,
    ValidationORM,
)
from app.db.repository import PersistenceRepository
from app.db.session import get_db
from app.main import app
from app.models.finding import ValidationStatus
from app.services.generic_local_web_validation import (
    GENERIC_LOCAL_WEB_SCENARIO,
    LocalTargetConnectionError,
)
from app.services.test_harness import TestHarnessPipeline
from tests.db_utils import make_test_session_factory
from tests.integration_apps.vulnerable_web_app import LocalVulnerableAppServer


class HarnessPersistenceTests(unittest.TestCase):

    def setUp(self):
        self.engine, self.factory = make_test_session_factory()
        self.pipeline = TestHarnessPipeline(mode="fixture", allowed_origins=[])

        def override_get_db():
            session = self.factory()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_test_harness_pipeline] = lambda: self.pipeline
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.pop(get_test_harness_pipeline, None)
        app.dependency_overrides.pop(get_db, None)
        self.engine.dispose()

    def post_fixture(self):
        return self.client.post(
            "/api/test-harness/run",
            json={
                "target_url": "http://127.0.0.1:8080/dvwa",
                "scenario": "public_app_validation",
                "authorized": True,
            },
        )

    def test_fixture_run_persists_and_is_retrievable_by_scan_api(self):
        response = self.post_fixture()
        self.assertEqual(response.status_code, 200)
        scan_id = response.json()["scan_id"]
        self.assertEqual(scan_id, response.json()["finding"]["scan_id"])

        session = self.factory()
        try:
            repository = PersistenceRepository(session)
            scans = list(session.scalars(select(ScanORM)))
            findings = repository.list_findings_for_scan(scan_id)
            chains = repository.list_attack_chains_for_scan(scan_id)
            candidate = next(
                finding for finding in findings
                if finding.vulnerability_type == "sql_injection"
            )

            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0].status, "completed")
            self.assertTrue(scans[0].authorized)
            self.assertIsNotNone(scans[0].completed_at)
            self.assertIsNone(scans[0].failure_reason)
            self.assertEqual(len(findings), 2)
            self.assertEqual(candidate.status, ValidationStatus.DETECTED)
            self.assertEqual(len(candidate.validations), 1)
            self.assertEqual(
                candidate.validations[0].status,
                ValidationStatus.CONFIRMED,
            )
            self.assertEqual(
                len(candidate.validations[0].evidence_records),
                1,
            )
            self.assertEqual(candidate.mitre_mappings[0].technique_id, "T1190")
            self.assertEqual(len(chains), 1)
            self.assertEqual(
                [step.step_number for step in chains[0].steps],
                [1, 2],
            )
        finally:
            session.close()

        fetched_scan = self.client.get(f"/api/scans/{scan_id}")
        fetched_findings = self.client.get(f"/api/scans/{scan_id}/findings")
        fetched_chains = self.client.get(f"/api/scans/{scan_id}/chains")
        self.assertEqual(fetched_scan.status_code, 200)
        self.assertEqual(fetched_scan.json()["status"], "completed")
        self.assertEqual(len(fetched_findings.json()), 2)
        self.assertEqual(len(fetched_chains.json()), 1)

    def test_generic_loopback_run_persists_all_validator_outputs(self):
        server = LocalVulnerableAppServer()
        try:
            origin = server.start()
            response = self.client.post(
                "/api/test-harness/run",
                json={
                    "target_url": origin,
                    "scenario": GENERIC_LOCAL_WEB_SCENARIO,
                    "authorized": True,
                },
            )
        finally:
            server.stop()

        self.assertEqual(response.status_code, 200)
        scan_id = response.json()["scan_id"]
        session = self.factory()
        try:
            self.assertEqual(
                session.scalar(select(func.count()).select_from(ScanORM)),
                1,
            )
            self.assertEqual(
                session.scalar(select(func.count()).select_from(FindingORM)),
                7,
            )
            self.assertEqual(
                session.scalar(select(func.count()).select_from(ValidationORM)),
                6,
            )
            self.assertEqual(
                session.scalar(select(func.count()).select_from(EvidenceORM)),
                6,
            )
            self.assertEqual(
                session.scalar(select(func.count()).select_from(MitreMappingORM)),
                3,
            )
            repository = PersistenceRepository(session)
            findings = repository.list_findings_for_scan(scan_id)
            chains = repository.list_attack_chains_for_scan(scan_id)
            self.assertTrue(all(finding.scan_id == scan_id for finding in findings))
            command_candidate = next(
                finding for finding in findings
                if finding.vulnerability_type == "command_execution"
            )
            self.assertEqual(
                command_candidate.status,
                ValidationStatus.DETECTED,
            )
            self.assertEqual(
                command_candidate.validations[0].status,
                ValidationStatus.CONFIRMED,
            )
            self.assertEqual(
                command_candidate.mitre_mappings[0].technique_id,
                "T1059.004",
            )
            self.assertTrue(
                command_candidate.validations[0].evidence_records[0]
                .evidence_json["execution_marker_present"]
            )
            ssrf_candidate = next(
                finding for finding in findings
                if finding.vulnerability_type == "ssrf"
            )
            self.assertEqual(ssrf_candidate.status, ValidationStatus.DETECTED)
            self.assertEqual(
                ssrf_candidate.validations[0].status,
                ValidationStatus.CONFIRMED,
            )
            self.assertTrue(
                ssrf_candidate.validations[0].evidence_records[0]
                .evidence_json["canary_content_marker_observed"]
            )
            self.assertEqual(ssrf_candidate.mitre_mappings, [])
            system_information_candidate = next(
                finding for finding in findings
                if finding.vulnerability_type == "system_information_discovery"
            )
            self.assertEqual(
                system_information_candidate.status,
                ValidationStatus.DETECTED,
            )
            self.assertEqual(
                system_information_candidate.validations[0].status,
                ValidationStatus.CONFIRMED,
            )
            self.assertEqual(
                system_information_candidate.mitre_mappings[0].technique_id,
                "T1082",
            )
            self.assertEqual(len(chains), 4)
            self.assertTrue(all(
                [step.step_number for step in chain.steps]
                == list(range(1, len(chain.steps) + 1))
                for chain in chains
            ))
            progression = next(
                chain for chain in chains
                if any(
                    step.technique_id == "T1059.004"
                    for step in chain.steps
                )
            )
            self.assertEqual(
                [step.technique_id for step in progression.steps],
                [None, "T1190", "T1059.004", "T1082"],
            )
            self.assertEqual(
                progression.steps[-2].capability,
                "command_execution",
            )
            self.assertEqual(
                progression.steps[-1].capability,
                "system_information",
            )
        finally:
            session.close()

        fetched_findings = self.client.get(f"/api/scans/{scan_id}/findings")
        fetched_chains = self.client.get(f"/api/scans/{scan_id}/chains")
        self.assertEqual(fetched_findings.status_code, 200)
        self.assertEqual(fetched_chains.status_code, 200)
        command_json = next(
            finding for finding in fetched_findings.json()
            if finding["vulnerability_type"] == "command_execution"
        )
        self.assertEqual(command_json["status"], ValidationStatus.DETECTED)
        self.assertEqual(
            command_json["validations"][0]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertTrue(any(
            any(step["technique_id"] == "T1059.004" for step in chain["steps"])
            for chain in fetched_chains.json()
        ))
        self.assertTrue(any(
            any(step["technique_id"] == "T1082" for step in chain["steps"])
            for chain in fetched_chains.json()
        ))

    def test_repeated_runs_remain_isolated(self):
        first = self.post_fixture().json()["scan_id"]
        second = self.post_fixture().json()["scan_id"]
        self.assertNotEqual(first, second)

        session = self.factory()
        try:
            repository = PersistenceRepository(session)
            first_findings = repository.list_findings_for_scan(first)
            second_findings = repository.list_findings_for_scan(second)
            self.assertEqual(len(first_findings), 2)
            self.assertEqual(len(second_findings), 2)
            self.assertTrue(all(item.scan_id == first for item in first_findings))
            self.assertTrue(all(item.scan_id == second for item in second_findings))
            self.assertTrue(
                {item.id for item in first_findings}.isdisjoint(
                    item.id for item in second_findings
                )
            )
        finally:
            session.close()

    def test_execution_failure_marks_started_scan_failed_safely(self):
        def fail_execution(_origin, *, scan_id):
            raise LocalTargetConnectionError("sensitive-detail-must-not-persist")

        pipeline = TestHarnessPipeline(
            mode="fixture",
            allowed_origins=[],
            generic_scenario_executor=fail_execution,
        )
        session = self.factory()
        try:
            with self.assertRaises(LocalTargetConnectionError):
                pipeline.run(
                    target_url="http://127.0.0.1:8090",
                    scenario=GENERIC_LOCAL_WEB_SCENARIO,
                    authorized=True,
                    persistence_session=session,
                )

            scans = list(session.scalars(select(ScanORM)))
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0].status, "failed")
            self.assertIsNotNone(scans[0].completed_at)
            self.assertEqual(
                scans[0].failure_reason,
                "LocalTargetConnectionError: controlled harness run failed",
            )
            self.assertNotIn("sensitive-detail", scans[0].failure_reason)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
