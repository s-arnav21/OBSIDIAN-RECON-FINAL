"""Regression tests for honesty gaps in validation and exploitation.

Each test pins one semantic guarantee:

* non-HTTP findings are never turned into HTTP errors;
* a validator-backed finding is never shadowed by an injected curl;
* exit-0 command output is an observation, not exploitation;
* a shell is reported only when explicitly evidenced;
* finding prerequisites are not mistaken for held capabilities.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.agent.models import AgentState
from app.api.attacks import _attempt_outcome, _shell_obtained
from app.models.finding import Finding, ValidationStatus
from app.models.scanner import RawFinding
from app.models.validation import ValidationStatus as ResultStatus
from app.services.attack_execution import execute_planned_attack
from app.services.exploit_planner import (
    ExploitPlan,
    _coerce_llm_plan,
    _default_probe_command,
)
from pipeline.validator import _validate


def _orm(**overrides) -> SimpleNamespace:
    values = {
        "validator_id": None,
        "endpoint": "http://example.test/item",
        "http_method": "GET",
        "target": "http://example.test",
        "vulnerability_type": "sqli",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class NonHttpValidationTests(unittest.TestCase):
    def test_preserved_bindshell_evidence_is_confirmed(self):
        finding = RawFinding(
            scanner="bindshell",
            scanner_template_id="root-bindshell",
            vulnerability_type="root-bindshell",
            target="10.0.0.5",
            url="bindshell://10.0.0.5:1524/",
            severity="critical",
            raw={"id_output": "uid=0(root)", "is_root": True, "is_shell": True},
        )
        result = _validate(finding, "10.0.0.5")
        self.assertEqual(result.status, ResultStatus.CONFIRMED)
        self.assertEqual(result.method, "scanner-protocol-evidence")
        self.assertEqual(result.evidence["protocol"], "bindshell")
        self.assertTrue(result.evidence["scanner_evidence"]["is_root"])

    def test_non_http_without_evidence_is_manual_review_not_error(self):
        finding = RawFinding(
            scanner="ftp",
            scanner_template_id="anonymous-ftp",
            vulnerability_type="anonymous-ftp",
            target="10.0.0.5",
            url="ftp://10.0.0.5/",
            severity="high",
            raw={},
        )
        result = _validate(finding, "10.0.0.5")
        self.assertEqual(result.status, ResultStatus.MANUAL_REVIEW)
        self.assertIsNone(result.error)

    def test_service_name_alone_is_context_not_proof(self):
        finding = RawFinding(
            scanner="ftp",
            scanner_template_id="anonymous-ftp",
            vulnerability_type="anonymous-ftp",
            target="10.0.0.5",
            service="ftp",
            port=21,
            url="ftp://10.0.0.5/",
            severity="high",
            raw={},
        )
        result = _validate(finding, "10.0.0.5")
        self.assertEqual(result.status, ResultStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["scanner_evidence"]["service"], "ftp")


class ExploitPlanHonestyTests(unittest.TestCase):
    def test_validator_backed_finding_gets_no_default_probe(self):
        self.assertIsNone(
            _default_probe_command(_orm(validator_id="validate-sqli"))
        )

    def test_manual_finding_gets_read_only_probe(self):
        command = _default_probe_command(_orm(validator_id=None))
        self.assertIn("curl", command)
        self.assertIn("$OBSIDIAN_ENDPOINT", command)

    def test_llm_command_cannot_shadow_validator(self):
        plan = _coerce_llm_plan(
            {"command": "curl http://example.test/item", "tooling": ["curl"]},
            _orm(validator_id="validate-sqli"),
            None,
        )
        self.assertIsNone(plan.command)
        self.assertIn("validate-sqli", plan.tooling)

    def test_llm_command_is_kept_without_validator(self):
        plan = _coerce_llm_plan(
            {"command": "curl http://example.test/item"},
            _orm(validator_id=None),
            None,
        )
        self.assertEqual(plan.command, "curl http://example.test/item")

    def test_execution_prefers_validator_over_a_plan_command(self):
        plan = ExploitPlan(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            source="llm",
            summary="validator must win",
            steps=[],
            command="echo command-ran",
        )
        finding = SimpleNamespace(validator_id="validate-sqli")
        validator_attempt = {
            "status": "confirmed",
            "method": "validator",
            "validator": "validate-sqli",
            "stdout": "validator evidence",
        }
        with patch(
            "app.services.attack_execution.attempt_validation",
            return_value=validator_attempt,
        ) as validate, patch(
            "app.services.attack_execution._run_command"
        ) as run_command:
            attempt = execute_planned_attack(plan, finding)
        validate.assert_called_once()
        run_command.assert_not_called()
        self.assertEqual(attempt["method"], "validator")


class OutcomeHonestyTests(unittest.TestCase):
    def test_observed_command_output_is_not_success(self):
        self.assertEqual(_attempt_outcome({"status": "observed"}), "inconclusive")

    def test_only_confirmed_is_success(self):
        self.assertEqual(
            _attempt_outcome({"status": ValidationStatus.CONFIRMED}),
            "success",
        )
        self.assertEqual(
            _attempt_outcome({"status": "success"}),
            "inconclusive",
        )

    def test_shell_requires_explicit_evidence(self):
        self.assertFalse(_shell_obtained({"status": "confirmed"}))
        self.assertFalse(_shell_obtained({"status": "observed", "stdout": "uid=0"}))
        self.assertTrue(_shell_obtained({"evidence": {"is_shell": True}}))
        self.assertTrue(
            _shell_obtained({"evidence": {"scanner_evidence": {"is_shell": True}}})
        )


class CapabilitySeedingTests(unittest.TestCase):
    def test_requires_are_not_seeded_as_capabilities(self):
        finding = Finding(
            finding_id="finding-gap",
            scan_id="scan-gap",
            asset_id="asset-gap",
            target="http://example.test",
            host="example.test",
            source="test",
            vulnerability_type="unmapped_gap_test",
            validation_status=ValidationStatus.CONFIRMED,
            requires_all=["domain_admin"],
            requires_any=["authenticated_session"],
            provides=["credential_access"],
        )
        state = AgentState.from_findings(
            scan_id="scan-gap",
            target="http://example.test",
            asset_id="asset-gap",
            authorized=True,
            findings=[finding],
        )
        self.assertNotIn("domain_admin", state.capabilities)
        self.assertNotIn("authenticated_session", state.capabilities)
        self.assertIn("credential_access", state.capabilities)
        self.assertIn("unauthenticated", state.capabilities)


class FrontendHonestyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        cls.js = (root / "FRONTEND" / "exploit.js").read_text(encoding="utf-8")
        cls.html = (root / "FRONTEND" / "exploit.html").read_text(
            encoding="utf-8"
        )

    def test_shell_row_requires_explicit_backend_evidence(self):
        self.assertIn("attempt.shell_obtained !== true", self.js)
        self.assertNotIn("shellRow.hidden = outcome", self.js)

    def test_excluded_findings_are_visible_with_a_reason(self):
        self.assertIn('id="excludedWrap"', self.html)
        self.assertIn("renderExcluded", self.js)
        self.assertIn("EXCLUSION_REASONS", self.js)


if __name__ == "__main__":
    unittest.main()
