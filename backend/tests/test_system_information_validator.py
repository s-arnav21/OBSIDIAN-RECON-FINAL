"""Tests for the fixed-token T1082 controlled simulation."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import Finding, ValidationStatus
from app.validation.dispatcher import dispatch
from app.validation.system_information import (
    BASELINE_DISCOVERY_TOKEN,
    CONTROL_DISCOVERY_TOKEN,
    DISCOVERY_PROBE_TOKEN,
    SYSTEM_INFORMATION_MARKER,
    validate_controlled_system_information_discovery,
)


class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code


class RecordingSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def post(self, url, data=None):
        self.calls.append((url, data))
        return next(self.responses)


def make_finding(**overrides):
    values = {
        "finding_id": "finding-system-information",
        "scan_id": "scan-system-information",
        "asset_id": "asset-system-information",
        "target": "http://127.0.0.1:8090",
        "host": "127.0.0.1",
        "port": 8090,
        "protocol": "http",
        "endpoint": "/admin/system-information",
        "source": "controlled_fixture",
        "template_id": "local-fixture-system-information-check",
        "validator_id": "controlled-http-system-information-discovery",
        "vulnerability_type": "system_information_discovery",
        "severity": "low",
        "http_method": "POST",
        "parameter_name": "discovery_token",
        "parameter_location": "form",
        "validation_status": ValidationStatus.DETECTED,
        "validation_confidence": 0.2,
        "evidence": {"caller_supplied_value": "must-not-be-sent"},
    }
    values.update(overrides)
    return Finding(**values)


class ControlledSystemInformationValidatorTests(unittest.TestCase):

    def test_unique_synthetic_marker_confirms(self):
        session = RecordingSession([
            FakeResponse("synthetic baseline"),
            FakeResponse(f"synthetic metadata: {SYSTEM_INFORMATION_MARKER}"),
            FakeResponse("synthetic control"),
        ])

        result = validate_controlled_system_information_discovery(
            make_finding(),
            session,
        )

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.confidence, 0.9)
        self.assertTrue(result.evidence["discovery_marker_present"])
        self.assertFalse(result.evidence["real_system_information_accessed"])
        self.assertFalse(result.evidence["external_requests_performed"])
        self.assertNotIn(SYSTEM_INFORMATION_MARKER, repr(result.evidence))
        self.assertEqual(
            [call[1]["discovery_token"] for call in session.calls],
            [
                BASELINE_DISCOVERY_TOKEN,
                DISCOVERY_PROBE_TOKEN,
                CONTROL_DISCOVERY_TOKEN,
            ],
        )
        self.assertNotIn("must-not-be-sent", repr(session.calls))

    def test_missing_synthetic_marker_rejects(self):
        session = RecordingSession([
            FakeResponse("baseline"),
            FakeResponse("no marker"),
            FakeResponse("control"),
        ])

        result = validate_controlled_system_information_discovery(
            make_finding(),
            session,
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["reason"],
            "synthetic_system_information_marker_not_observed",
        )

    def test_marker_collision_requires_manual_review(self):
        session = RecordingSession([
            FakeResponse("baseline"),
            FakeResponse(f"probe {SYSTEM_INFORMATION_MARKER}"),
            FakeResponse(f"control {SYSTEM_INFORMATION_MARKER}"),
        ])

        result = validate_controlled_system_information_discovery(
            make_finding(),
            session,
        )

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["reason"],
            "discovery_marker_not_unique_to_probe",
        )

    def test_non_loopback_target_fails_closed_without_request(self):
        session = RecordingSession([])

        result = validate_controlled_system_information_discovery(
            make_finding(
                target="https://example.com",
                host="example.com",
                port=443,
                protocol="https",
            ),
            session,
        )

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["reason"],
            "controlled_simulation_requires_loopback",
        )
        self.assertEqual(session.calls, [])

    def test_dispatcher_routes_registered_validator(self):
        session = RecordingSession([
            FakeResponse("baseline"),
            FakeResponse(f"probe {SYSTEM_INFORMATION_MARKER}"),
            FakeResponse("control"),
        ])

        result = dispatch(make_finding(), session=session)

        self.assertEqual(
            result.validator,
            "controlled_http_system_information_discovery",
        )
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)

    def test_confirmed_finding_maps_to_t1082(self):
        enriched = enrich_finding_model(make_finding(
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=0.9,
        ))

        self.assertEqual(enriched.mitre_technique_id, "T1082")
        self.assertEqual(
            enriched.mitre_technique_name,
            "System Information Discovery",
        )
        self.assertEqual(enriched.mitre_tactic, "Discovery")
        self.assertEqual(enriched.requires_any, ["command_execution"])
        self.assertEqual(enriched.provides, ["system_information"])

    def test_validator_has_no_operating_system_execution_api(self):
        module_path = (
            Path(__file__).resolve().parents[1]
            / "app"
            / "validation"
            / "system_information.py"
        )
        tree = ast.parse(module_path.read_text())

        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".")[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
        self.assertTrue(
            {"os", "subprocess", "socket"}.isdisjoint(imported_roots)
        )

        forbidden_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {
                "eval",
                "exec",
            }:
                forbidden_calls.append(node.func.id)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "system",
                "popen",
            }:
                forbidden_calls.append(node.func.attr)
        self.assertEqual(forbidden_calls, [])


if __name__ == "__main__":
    unittest.main()
