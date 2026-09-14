"""Persistence schema and repository tests using isolated SQLite."""

from __future__ import annotations

import unittest

from sqlalchemy.dialects import postgresql

from app.attack_chain.engine import build_attack_paths
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.db.base import Base
from app.db.models import EvidenceORM
from app.db.repository import PersistenceConflictError, PersistenceRepository
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from tests.db_utils import make_test_session_factory


def make_finding(**overrides) -> Finding:
    values = {
        "finding_id": "finding-db-sqli",
        "scan_id": "scan-db-one",
        "asset_id": "asset-db-one",
        "target": "http://127.0.0.1:8090",
        "host": "127.0.0.1",
        "port": 8090,
        "protocol": "http",
        "endpoint": "/items",
        "source": "database_test_scanner",
        "template_id": "database-test-sqli-template",
        "validator_id": "generic-http-sqli",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "http_method": "GET",
        "parameter_name": "id",
        "parameter_location": "query",
        "validation_status": ValidationStatus.DETECTED,
        "validation_confidence": 0.2,
    }
    values.update(overrides)
    return Finding(**values)


def confirmed_result() -> ValidationResult:
    return ValidationResult(
        status=ValidationStatus.CONFIRMED,
        confidence=0.9,
        validator="generic_http_sqli",
        method="boolean-response-differential SQLi",
        evidence={
            "decision": "confirmed",
            "reason": "stable_boolean_response_differential",
            "metrics": {"baseline_true_similarity": 1.0},
        },
    )


class PersistenceRepositoryTests(unittest.TestCase):

    def setUp(self):
        self.engine, factory = make_test_session_factory()
        self.session = factory()
        self.repository = PersistenceRepository(self.session)

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def create_scan_asset(self, scan_id="scan-db-one", asset_id="asset-db-one"):
        self.repository.create_scan(
            scan_id=scan_id,
            target_url="http://127.0.0.1:8090",
            authorized=True,
        )
        self.repository.persist_asset(
            scan_id=scan_id,
            asset_id=asset_id,
            hostname="127.0.0.1",
            base_url="http://127.0.0.1:8090",
        )

    def test_schema_contains_all_unified_tables(self):
        self.assertEqual(
            set(Base.metadata.tables),
            {
                "scans",
                "assets",
                "services",
                "findings",
                "validations",
                "evidence",
                "mitre_mappings",
                "attack_chains",
                "attack_chain_steps",
                "target_verifications",
                "exploit_sessions",
                "exploits",
                "shells",
            },
        )

    def test_scan_asset_and_service_relationships(self):
        self.create_scan_asset()
        service = self.repository.persist_service(
            service_id="service-db-http",
            scan_id="scan-db-one",
            asset_id="asset-db-one",
            port=8090,
            protocol="tcp",
            service_name="http",
            state="open",
            source="database_test_scanner",
        )
        self.session.commit()

        scan = self.repository.get_scan("scan-db-one")
        self.assertIsNotNone(scan)
        self.assertEqual([asset.id for asset in scan.assets], ["asset-db-one"])
        self.assertEqual([item.id for item in scan.services], [service.id])
        self.assertEqual(service.asset.scan_id, scan.id)

    def test_finding_validation_evidence_and_mapping_remain_separate(self):
        self.create_scan_asset()
        candidate = make_finding()
        self.repository.persist_finding(candidate)
        validation = self.repository.persist_validation(
            finding_id=candidate.finding_id,
            result=confirmed_result(),
            validation_id="validation-db-sqli",
        )
        evidence = self.repository.persist_evidence(
            evidence_id="evidence-db-sqli",
            validation_id=validation.id,
            finding_id=candidate.finding_id,
            evidence_type="validation_result",
            evidence_json=dict(confirmed_result().evidence),
        )
        enriched = enrich_finding_model(candidate)
        self.repository.persist_mitre_mapping(
            enriched,
            mapping_id="mapping-db-t1190",
            mapping_confidence=0.9,
        )
        self.session.commit()

        stored = self.repository.list_findings_for_scan(candidate.scan_id)[0]
        self.assertEqual(stored.status, ValidationStatus.DETECTED)
        self.assertEqual(stored.validations[0].status, ValidationStatus.CONFIRMED)
        self.assertEqual(stored.validations[0].id, validation.id)
        self.assertEqual(
            stored.validations[0].evidence_records[0].evidence_json,
            evidence.evidence_json,
        )
        self.assertEqual(
            stored.validations[0].evidence_records[0].evidence_json["metrics"],
            {"baseline_true_similarity": 1.0},
        )
        self.assertEqual(stored.mitre_mappings[0].technique_id, "T1190")

    def test_evidence_compiles_to_postgresql_jsonb(self):
        column_type = EvidenceORM.__table__.c.evidence_json.type
        self.assertEqual(
            column_type.compile(dialect=postgresql.dialect()),
            "JSONB",
        )

    def test_attack_chain_persistence_preserves_step_order(self):
        self.create_scan_asset()
        reachability = make_finding(
            finding_id="finding-db-reachability",
            vulnerability_type="service_scan",
            validator_id=None,
            template_id="database-test-health",
            endpoint="/health",
            parameter_name=None,
            parameter_location=None,
            http_method=None,
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=1.0,
        )
        exploit = enrich_finding_model(make_finding(
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=0.9,
        ))
        self.repository.persist_finding(reachability)
        self.repository.persist_finding(make_finding())
        chain = build_attack_paths([reachability, exploit])[0]
        self.repository.persist_attack_chain(chain)
        self.session.commit()

        stored = self.repository.list_attack_chains_for_scan("scan-db-one")[0]
        self.assertEqual(
            [step.step_number for step in stored.steps],
            [1, 2],
        )
        self.assertEqual(
            [step.finding_id for step in stored.steps],
            ["finding-db-reachability", "finding-db-sqli"],
        )
        self.assertEqual(stored.steps[1].technique_id, "T1190")

    def test_scan_retrieval_is_isolated_by_scan_id(self):
        for suffix in ("one", "two"):
            scan_id = f"scan-db-{suffix}"
            asset_id = f"asset-db-{suffix}"
            self.create_scan_asset(scan_id, asset_id)
            self.repository.persist_finding(make_finding(
                finding_id=f"finding-db-{suffix}",
                scan_id=scan_id,
                asset_id=asset_id,
            ))
        self.session.commit()

        first = self.repository.list_findings_for_scan("scan-db-one")
        second = self.repository.list_findings_for_scan("scan-db-two")
        self.assertEqual([finding.id for finding in first], ["finding-db-one"])
        self.assertEqual([finding.id for finding in second], ["finding-db-two"])

    def test_cross_scan_asset_reference_is_rejected(self):
        self.create_scan_asset("scan-db-one", "asset-db-one")
        self.create_scan_asset("scan-db-two", "asset-db-two")

        with self.assertRaisesRegex(
            PersistenceConflictError,
            "belongs to a different scan",
        ):
            self.repository.persist_service(
                scan_id="scan-db-two",
                asset_id="asset-db-one",
                port=8090,
            )


if __name__ == "__main__":
    unittest.main()
