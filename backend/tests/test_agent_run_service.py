"""End-to-end composition tests for one bounded agent workflow."""

from __future__ import annotations

from dataclasses import replace
import json
import unittest
from unittest.mock import patch

from app.agent.llm_client import LLMClientError
from app.agent.llm_planner import LLMPlanner
from app.agent.models import AgentState, AgentStatus
from app.agent.policy import PolicyDecisionCode
from app.agent.run_service import AgentRunService
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult


ORIGIN = "http://127.0.0.1:8090"
SCAN_ID = "scan-agent-run"
ASSET_ID = "asset-agent-run"


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


def _sqli_finding(identifier: str = "finding-sqli") -> Finding:
    return Finding(
        finding_id=identifier,
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
        evidence={"raw_secret": "must-not-enter-agent-trace"},
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
        parameter_name="diagnostic_token",
        parameter_location="form",
        severity="critical",
    )


def _state(*, findings=None, maximum_steps: int = 4) -> AgentState:
    return AgentState.from_findings(
        scan_id=SCAN_ID,
        target=ORIGIN,
        asset_id=ASSET_ID,
        authorized=True,
        findings=(
            [_reachability_finding(), _sqli_finding()]
            if findings is None
            else findings
        ),
        maximum_steps=maximum_steps,
    )


def _action_data(**updates):
    data = {
        "action_id": "action-sqli-1",
        "tool_id": "validate-sql-injection",
        "scan_id": SCAN_ID,
        "asset_id": ASSET_ID,
        "finding_id": "finding-sqli",
        "target": ORIGIN,
        "reason": "Use the registered deterministic validator.",
        "expected_capabilities": ["discovered_services"],
    }
    data.update(updates)
    return data


def _action_content(**updates) -> str:
    return json.dumps({
        "decision": "action",
        "action": _action_data(**updates),
    })


COMPLETE_CONTENT = json.dumps({"decision": "complete", "action": None})


class _FakeCompletionClient:
    def __init__(self, outcomes) -> None:
        self.outcomes = list(outcomes)
        self.calls = []

    def complete(self, messages, *, response_format):
        self.calls.append((messages, response_format))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _service(*outcomes):
    client = _FakeCompletionClient(outcomes)
    return AgentRunService(LLMPlanner(client)), client


def _confirmed_sqli(_finding, *, session=None) -> ValidationResult:
    del session
    return ValidationResult(
        status=ValidationStatus.CONFIRMED,
        confidence=0.9,
        validator="generic_http_sqli",
        method="test-controlled deterministic validation",
        evidence={"decision": "confirmed"},
    )


class AgentRunServiceTests(unittest.TestCase):
    def test_llm_action_runs_policy_executor_observation_and_state_update(self):
        service, client = _service(_action_content(), COMPLETE_CONTENT)
        initial = _state()

        with patch(
            "app.agent.executor.dispatch",
            side_effect=_confirmed_sqli,
        ) as deterministic_dispatch:
            result = service.run(initial, session=object())

        deterministic_dispatch.assert_called_once()
        self.assertEqual(result.status, AgentStatus.COMPLETED)
        self.assertEqual(result.stop_reason, "planner_completed")
        self.assertEqual(result.steps_used, 1)
        self.assertEqual(len(result.steps), 1)
        step = result.steps[0]
        self.assertEqual(step.proposed_action.tool_id, "validate-sql-injection")
        self.assertTrue(step.policy_decision.allowed)
        self.assertEqual(step.policy_decision.code, PolicyDecisionCode.ALLOWED)
        self.assertEqual(step.observation.validation_status, "confirmed")
        self.assertEqual(
            step.observation.capabilities_gained,
            ("application_compromise", "possible_database_access"),
        )
        self.assertEqual(
            result.final_state.finding_by_id("finding-sqli").validation_status,
            "confirmed",
        )
        self.assertEqual(
            result.final_state.finding_by_id("finding-sqli").mitre_technique_id,
            "T1190",
        )
        self.assertIn("application_compromise", result.final_state.capabilities)
        self.assertEqual(
            initial.finding_by_id("finding-sqli").validation_status,
            "detected",
        )
        serialized = str(result.to_dict())
        self.assertNotIn("must-not-enter-agent-trace", serialized)
        self.assertNotIn("raw_secret", serialized)
        self.assertEqual(len(client.calls), 2)

    def test_incompatible_tool_is_denied_without_execution(self):
        service, _client = _service(_action_content(
            tool_id="validate-reflected-xss",
        ))

        with patch("app.agent.executor.dispatch") as deterministic_dispatch:
            result = service.run(_state(), session=object())

        deterministic_dispatch.assert_not_called()
        self.assertEqual(result.status, AgentStatus.BLOCKED)
        self.assertEqual(
            result.stop_reason,
            PolicyDecisionCode.DENIED_INCOMPATIBLE_TOOL,
        )
        self.assertFalse(result.steps[0].policy_decision.allowed)

    def test_duplicate_tool_finding_pair_executes_only_once(self):
        service, _client = _service(
            _action_content(action_id="action-first"),
            _action_content(action_id="action-duplicate"),
        )

        with patch(
            "app.agent.executor.dispatch",
            side_effect=_confirmed_sqli,
        ) as deterministic_dispatch:
            result = service.run(_state(), session=object())

        deterministic_dispatch.assert_called_once()
        self.assertEqual(result.steps_used, 2)
        self.assertEqual(len(result.steps), 2)
        self.assertTrue(result.steps[0].policy_decision.allowed)
        self.assertEqual(
            result.steps[1].policy_decision.code,
            PolicyDecisionCode.DENIED_DUPLICATE,
        )
        self.assertEqual(result.stop_reason, PolicyDecisionCode.DENIED_DUPLICATE)

    def test_parameter_option_reaches_deterministic_validator(self):
        service, _client = _service(
            _action_content(
                action_id="action-param",
                options={"parameter_name": "term"},
            ),
            COMPLETE_CONTENT,
        )
        dispatched = []

        def recording_dispatch(finding, *, session=None):
            dispatched.append(finding)
            return _confirmed_sqli(finding, session=session)

        with patch(
            "app.agent.executor.dispatch",
            side_effect=recording_dispatch,
        ):
            result = service.run(_state(), session=object())

        self.assertEqual(result.status, AgentStatus.COMPLETED)
        self.assertEqual(result.steps_used, 1)
        self.assertEqual(dispatched[0].parameter_name, "term")
        self.assertEqual(
            result.steps[0].proposed_action.to_dict()["options"],
            {"parameter_name": "term"},
        )

    def test_reflection_retry_with_different_options_is_allowed(self):
        service, client = _service(
            _action_content(
                action_id="action-param-id",
                options={"parameter_name": "id"},
            ),
            _action_content(
                action_id="action-param-term",
                options={"parameter_name": "term"},
            ),
            COMPLETE_CONTENT,
        )

        with patch(
            "app.agent.executor.dispatch",
            side_effect=_confirmed_sqli,
        ) as deterministic_dispatch:
            result = service.run(_state(), session=object())

        self.assertEqual(deterministic_dispatch.call_count, 2)
        self.assertEqual(result.status, AgentStatus.COMPLETED)
        self.assertEqual(result.stop_reason, "planner_completed")
        self.assertEqual(result.steps_used, 2)
        self.assertTrue(result.steps[0].policy_decision.allowed)
        self.assertTrue(result.steps[1].policy_decision.allowed)

    def test_identical_option_retry_is_denied_as_duplicate(self):
        service, _client = _service(
            _action_content(
                action_id="action-param-a",
                options={"parameter_name": "id"},
            ),
            _action_content(
                action_id="action-param-b",
                options={"parameter_name": "id"},
            ),
        )

        with patch(
            "app.agent.executor.dispatch",
            side_effect=_confirmed_sqli,
        ):
            result = service.run(_state(), session=object())

        self.assertEqual(result.status, AgentStatus.BLOCKED)
        self.assertEqual(result.stop_reason, PolicyDecisionCode.DENIED_DUPLICATE)
        self.assertEqual(result.steps_used, 2)
        self.assertTrue(result.steps[0].policy_decision.allowed)
        self.assertEqual(
            result.steps[1].policy_decision.code,
            PolicyDecisionCode.DENIED_DUPLICATE,
        )

    def test_command_execution_simulation_requires_authorization_and_prerequisite(self):
        content = _action_content(
            action_id="action-command",
            tool_id="validate-command-execution-simulation",
            finding_id="finding-command",
            expected_capabilities=["application_compromise"],
        )

        unauthorized_state = replace(
            _state(findings=[_command_finding()]),
            authorized=False,
            capabilities=("unauthenticated", "application_compromise"),
        )
        unauthorized_service, _unauthorized_client = _service(content)
        with patch("app.agent.executor.dispatch") as deterministic_dispatch:
            result = unauthorized_service.run(
                unauthorized_state,
                session=object(),
            )
        deterministic_dispatch.assert_not_called()
        self.assertEqual(result.status, AgentStatus.BLOCKED)
        self.assertEqual(
            result.stop_reason,
            PolicyDecisionCode.DENIED_UNAUTHORIZED,
        )

        service, _client = _service(content, COMPLETE_CONTENT)
        state = replace(
            _state(findings=[_command_finding()]),
            capabilities=("unauthenticated", "application_compromise"),
        )
        with patch(
            "app.agent.executor.dispatch",
            side_effect=_confirmed_sqli,
        ) as deterministic_dispatch:
            result = service.run(state, session=object())

        deterministic_dispatch.assert_called_once()
        self.assertEqual(result.status, AgentStatus.COMPLETED)
        self.assertEqual(result.stop_reason, "planner_completed")
        self.assertEqual(result.steps_used, 1)
        step = result.steps[0]
        self.assertTrue(step.policy_decision.allowed)
        self.assertEqual(
            step.policy_decision.code,
            PolicyDecisionCode.ALLOWED,
        )
        self.assertEqual(
            result.final_state.finding_by_id("finding-command").validation_status,
            "confirmed",
        )

    def test_malformed_or_failed_provider_output_returns_bounded_failure(self):
        cases = (
            ("not-json",),
            (LLMClientError("network_error"),),
        )
        for outcomes in cases:
            with self.subTest(outcomes=outcomes):
                service, _client = _service(*outcomes)
                with patch(
                    "app.agent.executor.dispatch"
                ) as deterministic_dispatch:
                    result = service.run(_state(), session=object())

                deterministic_dispatch.assert_not_called()
                self.assertEqual(result.status, AgentStatus.FAILED)
                self.assertEqual(result.stop_reason, "planner_error")
                self.assertEqual(result.steps_used, 0)
                self.assertEqual(result.steps, ())
                self.assertNotIn("network", str(result.to_dict()))

    def test_unknown_tool_fails_closed_before_executor(self):
        service, _client = _service(_action_content(tool_id="unknown-tool"))

        with patch("app.agent.executor.dispatch") as deterministic_dispatch:
            result = service.run(_state(), session=object())

        deterministic_dispatch.assert_not_called()
        self.assertEqual(result.status, AgentStatus.FAILED)
        self.assertEqual(result.stop_reason, "planner_error")
        self.assertEqual(result.steps, ())

    def test_changed_trusted_identity_fails_closed(self):
        changes = (
            {"scan_id": "scan-other"},
            {"asset_id": "asset-other"},
            {"target": "http://127.0.0.1:9090"},
            {"finding_id": "finding-other"},
        )
        for changed in changes:
            with self.subTest(changed=changed):
                service, _client = _service(_action_content(**changed))
                with patch(
                    "app.agent.executor.dispatch"
                ) as deterministic_dispatch:
                    result = service.run(_state(), session=object())

                deterministic_dispatch.assert_not_called()
                self.assertEqual(result.status, AgentStatus.FAILED)
                self.assertEqual(result.stop_reason, "planner_error")
                self.assertEqual(result.steps, ())

    def test_absolute_configured_step_bound_stops_without_extra_plan(self):
        second = _sqli_finding("finding-sqli-2")
        service, client = _service(
            _action_content(action_id="action-one"),
            _action_content(
                action_id="action-two",
                finding_id="finding-sqli-2",
            ),
            COMPLETE_CONTENT,
        )
        state = _state(
            findings=[_reachability_finding(), _sqli_finding(), second],
            maximum_steps=2,
        )

        with patch(
            "app.agent.executor.dispatch",
            side_effect=_confirmed_sqli,
        ) as deterministic_dispatch:
            result = service.run(state, session=object())

        self.assertEqual(deterministic_dispatch.call_count, 2)
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(result.steps_used, 2)
        self.assertEqual(result.status, AgentStatus.BLOCKED)
        self.assertEqual(result.stop_reason, "step_limit_reached")

    def test_no_eligible_action_allows_clean_planner_stop(self):
        service, client = _service(COMPLETE_CONTENT)
        state = _state(findings=[_reachability_finding()])

        with patch("app.agent.executor.dispatch") as deterministic_dispatch:
            result = service.run(state, session=object())

        deterministic_dispatch.assert_not_called()
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(result.status, AgentStatus.COMPLETED)
        self.assertEqual(result.stop_reason, "planner_completed")
        self.assertEqual(result.steps_used, 0)
        self.assertEqual(result.steps, ())

    def test_result_preserves_trusted_scan_context(self):
        service, _client = _service(COMPLETE_CONTENT)
        initial = _state()

        result = service.run(initial)

        self.assertEqual(result.final_state.scan_id, initial.scan_id)
        self.assertEqual(result.final_state.asset_id, initial.asset_id)
        self.assertEqual(result.final_state.target, initial.target)
        self.assertEqual(result.final_state.authorized, initial.authorized)


if __name__ == "__main__":
    unittest.main()
