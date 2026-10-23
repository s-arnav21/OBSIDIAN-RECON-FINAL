"""Tests for the MITRE technique automation layer (app.automation)."""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from app.agent.models import AgentAction, AgentState, AgentStatus
from app.agent.policy import PolicyDecision
from app.agent.run_service import AgentRunService
from app.automation import all_techniques, get_technique, technique_tool_catalog
from app.automation import runner
from app.automation.base import (
    AutomationContext,
    TechniqueResult,
    TechniqueStatus,
)
from app.automation.policy import (
    TECHNIQUE_TOOL_PREFIX,
    TechniquePolicyDecisionCode,
    TechniquePolicyGate,
)
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult


ORIGIN = "http://127.0.0.1:8090"
OTHER_ORIGIN = "http://127.0.0.1:9999"
SCAN_ID = "scan-automation"
ASSET_ID = "asset-automation"

EXPECTED_TECHNIQUES = {
    "T1595",
    "T1190",
    "T1059.004",
    "T1082",
    "T1078",
    "T1213",
    "T1548",
    "T1068",
}


def _reachability_finding() -> Finding:
    return Finding(
        finding_id="finding-reachability",
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        target=ORIGIN,
        host="127.0.0.1",
        source="http_discovery",
        vulnerability_type="service_scan",
        endpoint="/",
        severity="info",
        validation_status=ValidationStatus.CONFIRMED,
        validation_confidence=1.0,
    )


def _sqli_finding() -> Finding:
    return Finding(
        finding_id="finding-sqli",
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        target=ORIGIN,
        host="127.0.0.1",
        source="nuclei",
        vulnerability_type="sql_injection",
        validator_id="generic-http-sqli",
        template_id="scanner-sqli-candidate",
        endpoint="/items",
        http_method="GET",
        parameter_name="id",
        parameter_location="query",
        severity="high",
    )


def _command_finding() -> Finding:
    return Finding(
        finding_id="finding-command",
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        target=ORIGIN,
        host="127.0.0.1",
        source="controlled_fixture",
        vulnerability_type="command_execution",
        validator_id="generic-http-command-execution",
        endpoint="/admin/diagnostics",
        http_method="POST",
        parameter_name="cmd",
        parameter_location="form",
        severity="critical",
    )


def _state(*, authorized: bool = True, maximum_steps: int = 6) -> AgentState:
    return AgentState.from_findings(
        scan_id=SCAN_ID,
        target=ORIGIN,
        asset_id=ASSET_ID,
        authorized=authorized,
        findings=(
            _reachability_finding(),
            _sqli_finding(),
            _command_finding(),
        ),
        maximum_steps=maximum_steps,
    )


def _action(tool_id: str, finding_id: str, **updates) -> AgentAction:
    data = {
        "action_id": f"action-{tool_id}-{finding_id}",
        "tool_id": tool_id,
        "scan_id": SCAN_ID,
        "asset_id": ASSET_ID,
        "finding_id": finding_id,
        "target": ORIGIN,
        "reason": "Automated technique selection.",
        "expected_capabilities": [],
    }
    data.update(updates)
    return AgentAction.from_dict(data)


class _ScriptedPlanner:
    def __init__(self, actions):
        self.actions = list(actions)
        self.available_tool_ids = []

    def propose_action(self, state, available_tools):
        self.available_tool_ids = {
            tool["tool_id"] for tool in available_tools
        }
        if not self.actions:
            return None
        action = self.actions.pop(0)
        if callable(action):
            return action(state, available_tools)
        return action


def _confirmed(*_args, **_kwargs) -> ValidationResult:
    return ValidationResult(
        status=ValidationStatus.CONFIRMED,
        confidence=0.9,
        validator="generic_http",
        method="deterministic probe",
        evidence={"decision": "confirmed"},
    )


class RegistryTests(unittest.TestCase):
    def test_all_eight_techniques_registered(self):
        ids = {script.technique_id for script in all_techniques()}
        self.assertEqual(ids, EXPECTED_TECHNIQUES)

    def test_each_technique_describes_required_fields(self):
        for script in all_techniques():
            spec = script.describe()
            for field in (
                "technique_id",
                "name",
                "tactic",
                "description",
                "requires_any",
                "provides",
                "automatic_allowed",
            ):
                self.assertIn(field, spec, script.technique_id)
            self.assertTrue(spec["name"], script.technique_id)

    def test_tool_catalog_prefixes_technique_ids(self):
        catalog = technique_tool_catalog()
        ids = {entry["tool_id"] for entry in catalog}
        for technique_id in EXPECTED_TECHNIQUES:
            self.assertIn(f"{TECHNIQUE_TOOL_PREFIX}{technique_id}", ids)

    def test_unknown_technique_lookup_raises(self):
        with self.assertRaises(KeyError):
            get_technique("T9999")


class PolicyGateTests(unittest.TestCase):
    def setUp(self):
        self.gate = TechniquePolicyGate()

    def test_allows_satisfied_prerequisite(self):
        decision = self.gate.evaluate(
            _action("technique:T1190", "finding-sqli"), _state()
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.code, TechniquePolicyDecisionCode.ALLOWED)

    def test_denies_unauthorized(self):
        decision = self.gate.evaluate(
            _action("technique:T1190", "finding-sqli"),
            _state(authorized=False),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.code, TechniquePolicyDecisionCode.DENIED_UNAUTHORIZED
        )

    def test_denies_out_of_scope_target(self):
        decision = self.gate.evaluate(
            _action(
                "technique:T1190",
                "finding-sqli",
                target=OTHER_ORIGIN,
            ),
            _state(),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.code, TechniquePolicyDecisionCode.DENIED_SCOPE
        )

    def test_denies_unknown_tool(self):
        decision = self.gate.evaluate(
            _action("technique:T9999", "finding-sqli"), _state()
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.code, TechniquePolicyDecisionCode.DENIED_UNKNOWN_TOOL
        )

    def test_denies_missing_prerequisite(self):
        # T1059.004 needs application_compromise, absent on a fresh state.
        decision = self.gate.evaluate(
            _action("technique:T1059.004", "finding-command"), _state()
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.code, TechniquePolicyDecisionCode.DENIED_PREREQUISITE
        )

    def test_denies_wrong_finding(self):
        decision = self.gate.evaluate(
            _action("technique:T1190", "finding-absent"), _state()
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.code, TechniquePolicyDecisionCode.DENIED_WRONG_FINDING
        )

    def test_denies_step_limit(self):
        state = replace(_state(maximum_steps=1), current_step=1)
        decision = self.gate.evaluate(
            _action("technique:T1190", "finding-sqli"), state
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.code, TechniquePolicyDecisionCode.DENIED_STEP_LIMIT
        )

    def test_denies_duplicate(self):
        state = _state()
        action = _action("technique:T1190", "finding-sqli")
        execution = runner.run_technique_execution(
            action,
            state,
            PolicyDecision(
                action_id=action.action_id,
                tool_id=action.tool_id,
                finding_id=action.finding_id,
                allowed=True,
                code=TechniquePolicyDecisionCode.ALLOWED,
                reason="seeded",
            ),
        )
        from app.agent.orchestrator import _apply_execution

        advanced = _apply_execution(state, execution)
        decision = self.gate.evaluate(action, advanced)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.code, TechniquePolicyDecisionCode.DENIED_DUPLICATE
        )


class RunnerTests(unittest.TestCase):
    def test_context_and_result_are_bounded(self):
        finding = _sqli_finding()
        ctx = AutomationContext(
            target=ORIGIN,
            authorized=True,
            finding=finding,
            options={},
            capabilities=("discovered_services",),
        )
        result = TechniqueResult(
            technique_id="T1190",
            status=TechniqueStatus.CONFIRMED,
            summary="x" * 5000,
            evidence={"k": "v" * 5000},
        )
        self.assertLessEqual(len(result.summary), 512)
        self.assertLessEqual(len(result.evidence["k"]), 2000)
        self.assertEqual(ctx.merged_options()["endpoint"], "/items")
        self.assertEqual(ctx.merged_options()["parameter_name"], "id")

    def test_run_technique_never_raises(self):
        class _Boom:
            technique_id = "T0000"
            automatic_allowed = True

            def execute(self, ctx):
                raise RuntimeError("boom")

        with patch(
            "app.automation.runner.get_technique", return_value=_Boom()
        ):
            result = runner.run_technique(
                "T0000", AutomationContext(target=ORIGIN, authorized=True)
            )
        self.assertEqual(result.status, TechniqueStatus.ERROR)
        self.assertIn("boom", result.error)

    def test_blocked_technique_is_non_terminal(self):
        ctx = AutomationContext(target=ORIGIN, authorized=True)
        with patch(
            "app.automation.delivery.cached_script_path", return_value=None
        ), patch(
            "app.automation.delivery.remote_fetch_allowed", return_value=False
        ):
            result = runner.run_technique("T1068", ctx)
        self.assertEqual(result.status, TechniqueStatus.BLOCKED)

        action = _action("technique:T1068", "finding-command")
        execution = runner.run_technique_execution(
            action,
            _state(),
            PolicyDecision(
                action_id=action.action_id,
                tool_id=action.tool_id,
                finding_id=action.finding_id,
                allowed=True,
                code=TechniquePolicyDecisionCode.ALLOWED,
                reason="seeded",
            ),
        )
        from app.agent.models import AgentExecutionStatus

        self.assertEqual(
            execution.observation.execution_status,
            AgentExecutionStatus.COMPLETED,
        )
        self.assertEqual(execution.observation.error_category, "privesc_enumerator_unavailable")


def _view(*, reachability_confirmed: bool, observations=None):
    state = _state().to_dict()
    if not reachability_confirmed:
        for finding in state["findings"]:
            if finding["finding_id"] == "finding-reachability":
                finding["validation_status"] = "detected"
    state["observations"] = list(observations or [])
    return state


class ChainPlannerTests(unittest.TestCase):
    def test_starts_with_active_scanning(self):
        from app.automation.chain import ChainPlanner

        action = ChainPlanner().propose_action(
            _view(reachability_confirmed=False), []
        )
        self.assertIsNotNone(action)
        self.assertEqual(action.tool_id, "technique:T1595")

    def test_advances_to_web_exploit_after_discovery(self):
        from app.automation.chain import ChainPlanner

        action = ChainPlanner().propose_action(
            _view(
                reachability_confirmed=True,
                observations=[{
                    "tool_id": "technique:T1595",
                    "finding_id": "finding-reachability",
                    "policy_allowed": True,
                    "capabilities_gained": ["discovered_services"],
                }],
            ),
            [],
        )
        self.assertIsNotNone(action)
        self.assertEqual(action.tool_id, "technique:T1190")
        self.assertEqual(action.finding_id, "finding-sqli")

    def test_waits_for_command_execution_before_post_exploitation(self):
        from app.automation.chain import ChainPlanner

        action = ChainPlanner().propose_action(
            _view(
                reachability_confirmed=True,
                observations=[{
                    "tool_id": "technique:T1190",
                    "finding_id": "finding-sqli",
                    "policy_allowed": True,
                    "capabilities_gained": [
                        "application_compromise",
                        "possible_database_access",
                    ],
                }],
            ),
            [],
        )
        self.assertIsNotNone(action)
        # T1059.004 (shell) is unlocked by the compromise; the command-execution
        # dependent techniques are not yet applicable.
        self.assertEqual(action.tool_id, "technique:T1059.004")


class EndToEndChainTests(unittest.TestCase):
    def test_confirmed_chain_advances_capabilities(self):
        planner = _ScriptedPlanner([
            _action("technique:T1190", "finding-sqli"),
            _action("technique:T1059.004", "finding-command"),
            _action("technique:T1082", "finding-command"),
        ])
        service = AgentRunService(planner)
        with patch(
            "app.automation.adapters.run_validator", side_effect=_confirmed
        ):
            result = service.run(_state(), session=object())

        self.assertEqual(result.status, AgentStatus.COMPLETED)
        self.assertEqual(result.steps_used, 3)
        capabilities = set(result.final_state.capabilities)
        self.assertIn("application_compromise", capabilities)
        self.assertIn("command_execution", capabilities)
        self.assertIn("system_information", capabilities)
        self.assertEqual(
            result.steps[0].observation.capabilities_gained,
            ("application_compromise", "possible_database_access"),
        )
        self.assertTrue(
            all(step.policy_decision.allowed for step in result.steps)
        )

    def test_technique_tools_are_offered_to_the_planner(self):
        planner = _ScriptedPlanner([])
        service = AgentRunService(planner)
        service.run(_state(), session=object())
        self.assertIn(
            f"{TECHNIQUE_TOOL_PREFIX}T1190", planner.available_tool_ids
        )

    def test_unmet_prerequisite_blocks_the_run(self):
        planner = _ScriptedPlanner([
            _action("technique:T1059.004", "finding-command"),
        ])
        service = AgentRunService(planner)
        result = service.run(_state(), session=object())
        self.assertEqual(result.status, AgentStatus.BLOCKED)
        self.assertEqual(result.stop_reason, "denied_prerequisite")


if __name__ == "__main__":
    unittest.main()
