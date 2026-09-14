"""Deterministic security tests for the provider-independent LLM planner."""

from __future__ import annotations

from dataclasses import replace
import json
import unittest
from unittest.mock import patch

import httpx

from app.agent.executor import AgentToolExecutor
from app.agent.llm_client import (
    LLMClientConfig,
    LLMClientError,
    OpenAICompatibleClient,
)
from app.agent.llm_planner import (
    AGENT_ACTION_RESPONSE_FORMAT,
    LLMPlanner,
    LLMPlanningError,
)
from app.agent.models import AgentObservation, AgentState, AgentStatus
from app.agent.orchestrator import AgentOrchestrator
from app.agent.policy import AgentPolicyGate
from app.agent.tools import AgentToolRegistry
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult


ORIGIN = "http://127.0.0.1:8090"
SCAN_ID = "scan-llm-1"
ASSET_ID = "asset-llm-1"
FINDING_ID = "finding-exposure-1"
TEST_API_KEY = "test-provider-key-must-stay-private"


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


def _exposure_finding() -> Finding:
    return Finding(
        finding_id=FINDING_ID,
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        target=ORIGIN,
        host="127.0.0.1",
        source="nuclei",
        vulnerability_type="information_disclosure",
        validator_id="generic-http-exposed-resource",
        template_id="debug-resource",
        endpoint="/debug/config",
        http_method="GET",
        severity="high",
        evidence={"api_key": "finding-secret-must-not-reach-model"},
        http_request_context={
            "header": {"Authorization": "request-secret-must-not-reach-model"}
        },
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
        endpoint="/diagnostics",
        http_method="POST",
        parameter_name="command",
        parameter_location="form",
    )


def _state(*, findings=None, maximum_steps=3) -> AgentState:
    return AgentState.from_findings(
        scan_id=SCAN_ID,
        target=ORIGIN,
        asset_id=ASSET_ID,
        authorized=True,
        findings=(
            [_reachability_finding(), _exposure_finding()]
            if findings is None
            else findings
        ),
        maximum_steps=maximum_steps,
    )


def _action_data(**updates):
    data = {
        "action_id": "llm-action-1",
        "tool_id": "validate-exposed-resource",
        "scan_id": SCAN_ID,
        "asset_id": ASSET_ID,
        "finding_id": FINDING_ID,
        "target": ORIGIN,
        "reason": "Validate the candidate with the registered deterministic tool.",
        "expected_capabilities": ["discovered_services"],
    }
    data.update(updates)
    return data


def _action_content(**updates) -> str:
    return json.dumps({"decision": "action", "action": _action_data(**updates)})


COMPLETE_CONTENT = json.dumps({"decision": "complete", "action": None})


class FakeCompletionClient:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def complete(self, messages, *, response_format):
        self.calls.append((messages, response_format))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class BenignResponse:
    status_code = 200
    text = "ordinary public page with no sensitive configuration signals"
    headers = {"content-type": "text/plain"}


class BenignScopedSession:
    def __init__(self):
        self.urls = []

    def get(self, url):
        self.urls.append(url)
        return BenignResponse()


def _runtime(planner: LLMPlanner) -> AgentOrchestrator:
    registry = AgentToolRegistry()
    policy = AgentPolicyGate(registry)
    executor = AgentToolExecutor(registry, policy)
    return AgentOrchestrator(
        registry=registry,
        executor=executor,
        planner=planner,
    )


class LLMPlannerParsingTests(unittest.TestCase):
    def setUp(self):
        self.state = _state()
        self.tools = AgentToolRegistry().planner_catalog()

    def plan(self, content):
        return LLMPlanner(FakeCompletionClient([content])).propose_action(
            self.state.to_dict(),
            self.tools,
        )

    def test_valid_json_maps_to_existing_agent_action(self):
        planned = self.plan(_action_content())
        self.assertEqual(planned.tool_id, "validate-exposed-resource")
        self.assertEqual(planned.finding_id, FINDING_ID)
        self.assertEqual(planned.scan_id, SCAN_ID)
        self.assertEqual(planned.expected_capabilities, ("discovered_services",))

    def test_valid_json_with_supported_options_maps_to_agent_action(self):
        planned = self.plan(_action_content(options={"endpoint": "/debug/health"}))
        self.assertEqual(planned.tool_id, "validate-exposed-resource")
        self.assertEqual(
            dict(planned.options),
            {"endpoint": "/debug/health"},
        )
        self.assertEqual(
            planned.to_dict()["options"],
            {"endpoint": "/debug/health"},
        )

    def test_unknown_or_malformed_option_is_rejected_closed(self):
        cases = (
            {"payload": "x"},
            {123: "x"},
            {"endpoint": 5},
            {"endpoint": "line\nbreak"},
        )
        for options in cases:
            with self.subTest(options=options):
                with self.assertRaises(LLMPlanningError) as raised:
                    self.plan(_action_content(options=options))
                self.assertEqual(raised.exception.category, "invalid_schema")

    def test_planner_receives_tool_allowlist_and_reflection_observation_fields(self):
        observation = AgentObservation(
            action_id="obs-1",
            tool_id="validate-exposed-resource",
            finding_id=FINDING_ID,
            policy_decision="allowed",
            policy_allowed=True,
            execution_status="completed",
            validation_status="manual_review",
            summary="Inconclusive; different targeting may confirm.",
            validation_decision="incomplete_or_ambiguous_coverage",
            detection_methods=("boolean-response-differential",),
            observed_http_status=200,
            observed_response_length=512,
            waf_or_filter_interference=False,
            options_used=(("endpoint", "/debug/config"),),
        )
        state = self.state.to_dict()
        state["observations"] = [observation.to_dict()]
        client = FakeCompletionClient([COMPLETE_CONTENT])
        planner = LLMPlanner(client)

        self.assertIsNone(planner.propose_action(state, self.tools))

        transmitted = client.calls[0][0][-1]["content"]
        self.assertIn("allowed_options", transmitted)
        self.assertIn("validation_decision", transmitted)
        self.assertIn("detection_methods", transmitted)
        self.assertIn("observed_http_status", transmitted)
        self.assertIn("waf_or_filter_interference", transmitted)
        self.assertIn("options_used", transmitted)

    def test_explicit_completion_maps_to_none(self):
        self.assertIsNone(self.plan(COMPLETE_CONTENT))

    def test_invalid_json_fails_closed(self):
        with self.assertRaises(LLMPlanningError) as raised:
            self.plan("```json\nnot valid json\n```")
        self.assertEqual(raised.exception.category, "invalid_json")

    def test_malformed_unicode_fails_without_echoing_provider_content(self):
        with self.assertRaises(LLMPlanningError) as raised:
            self.plan("\ud800")
        self.assertEqual(raised.exception.category, "invalid_schema")
        self.assertNotIn("\\ud800", str(raised.exception))

    def test_missing_required_action_field_fails_closed(self):
        data = _action_data()
        del data["finding_id"]
        content = json.dumps({"decision": "action", "action": data})
        with self.assertRaises(LLMPlanningError) as raised:
            self.plan(content)
        self.assertEqual(raised.exception.category, "invalid_schema")

    def test_unknown_tool_fails_closed_before_policy_execution(self):
        with self.assertRaises(LLMPlanningError) as raised:
            self.plan(_action_content(tool_id="unregistered-shell"))
        self.assertEqual(raised.exception.category, "unknown_tool")

    def test_executable_or_reasoning_fields_are_not_accepted(self):
        for field in (
            "command",
            "payload",
            "url",
            "scanner_flags",
            "python",
            "reasoning",
            "authorized",
            "maximum_steps",
            "validation_status",
        ):
            with self.subTest(field=field):
                content = json.dumps({
                    "decision": "action",
                    "action": {**_action_data(), field: "untrusted"},
                })
                with self.assertRaises(LLMPlanningError) as raised:
                    self.plan(content)
                self.assertEqual(raised.exception.category, "invalid_schema")

    def test_changed_scan_asset_target_or_finding_reference_is_rejected(self):
        changes = (
            {"scan_id": "scan-other"},
            {"asset_id": "asset-other"},
            {"target": "http://127.0.0.1:9090"},
            {"finding_id": "finding-other"},
        )
        for changed in changes:
            with self.subTest(changed=changed):
                with self.assertRaises(LLMPlanningError) as raised:
                    self.plan(_action_content(**changed))
                self.assertEqual(raised.exception.category, "invalid_reference")

    def test_top_level_unknown_fields_are_rejected(self):
        content = json.dumps({
            "decision": "action",
            "action": _action_data(),
            "chain_of_thought": "untrusted reasoning",
        })
        with self.assertRaises(LLMPlanningError) as raised:
            self.plan(content)
        self.assertEqual(raised.exception.category, "invalid_schema")

    def test_duplicate_json_keys_are_rejected(self):
        content = (
            '{"decision":"complete","decision":"action","action":null}'
        )
        with self.assertRaises(LLMPlanningError) as raised:
            self.plan(content)
        self.assertEqual(raised.exception.category, "invalid_schema")

    def test_only_projected_sanitized_state_reaches_client(self):
        state = self.state.to_dict()
        state["api_key"] = "top-level-secret"
        state["findings"][1]["evidence"] = "nested-secret"
        state["observations"] = []
        client = FakeCompletionClient([COMPLETE_CONTENT])
        planner = LLMPlanner(client)

        self.assertIsNone(planner.propose_action(state, self.tools))

        transmitted = str(client.calls[0][0])
        self.assertNotIn("top-level-secret", transmitted)
        self.assertNotIn("nested-secret", transmitted)
        self.assertNotIn("api_key", transmitted)
        self.assertNotIn("evidence", transmitted)
        self.assertEqual(client.calls[0][1], AGENT_ACTION_RESPONSE_FORMAT)

    def test_provider_network_and_timeout_failures_are_bounded(self):
        cases = (
            (LLMClientError("network_error"), "provider_failure"),
            (LLMClientError("timeout"), "provider_timeout"),
            (RuntimeError("provider-secret"), "provider_failure"),
        )
        for provider_error, expected_category in cases:
            with self.subTest(expected_category=expected_category):
                planner = LLMPlanner(FakeCompletionClient([provider_error]))
                with self.assertRaises(LLMPlanningError) as raised:
                    planner.propose_action(self.state.to_dict(), self.tools)
                self.assertEqual(raised.exception.category, expected_category)
                self.assertNotIn("secret", str(raised.exception))


class OpenAICompatibleClientTests(unittest.TestCase):
    def config(self, **updates):
        values = {
            "base_url": "http://provider.test/v1",
            "api_key": TEST_API_KEY,
            "model": "planner-model-a",
            "timeout_seconds": 7,
        }
        values.update(updates)
        return LLMClientConfig(**values)

    def test_standard_chat_request_uses_configured_model_and_ignores_reasoning(self):
        captured = {}

        def handler(request):
            captured["url"] = str(request.url)
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={
                "choices": [{
                    "message": {
                        "content": COMPLETE_CONTENT,
                        "reasoning_content": "raw-chain-of-thought-secret",
                    }
                }]
            })

        client = OpenAICompatibleClient(
            self.config(model="replaceable-model-b"),
            transport=httpx.MockTransport(handler),
        )
        content = client.complete(
            [{"role": "user", "content": "bounded context"}],
            response_format=AGENT_ACTION_RESPONSE_FORMAT,
        )

        self.assertEqual(content, COMPLETE_CONTENT)
        self.assertNotIn("chain-of-thought", content)
        self.assertEqual(captured["url"], "http://provider.test/v1/chat/completions")
        self.assertEqual(captured["body"]["model"], "replaceable-model-b")
        self.assertFalse(captured["body"]["stream"])
        self.assertEqual(
            captured["body"]["response_format"],
            AGENT_ACTION_RESPONSE_FORMAT,
        )

    def test_environment_configuration_is_replaceable_and_key_repr_is_redacted(self):
        config = LLMClientConfig.from_environment({
            "AGENT_LLM_BASE_URL": "https://gateway.example/v1",
            "AGENT_LLM_API_KEY": TEST_API_KEY,
            "AGENT_LLM_MODEL": "different-model",
            "AGENT_LLM_TIMEOUT": "9.5",
        })
        self.assertEqual(config.model, "different-model")
        self.assertEqual(config.timeout_seconds, 9.5)
        self.assertNotIn(TEST_API_KEY, repr(config))
        self.assertIn("redacted", repr(config))

        with self.assertRaises(LLMClientError) as raised:
            LLMClientConfig.from_environment({
                "AGENT_LLM_BASE_URL": "https://gateway.example/v1",
                "AGENT_LLM_API_KEY": "",
                "AGENT_LLM_MODEL": "different-model",
            })
        self.assertEqual(raised.exception.category, "configuration_error")
        self.assertNotIn(TEST_API_KEY, str(raised.exception))

    def test_network_error_does_not_leak_key_or_transport_details(self):
        def handler(request):
            raise httpx.ConnectError(
                f"provider failed with {TEST_API_KEY}",
                request=request,
            )

        client = OpenAICompatibleClient(
            self.config(),
            transport=httpx.MockTransport(handler),
        )
        with self.assertRaises(LLMClientError) as raised:
            client.complete(
                [{"role": "user", "content": "context"}],
                response_format=AGENT_ACTION_RESPONSE_FORMAT,
            )
        self.assertEqual(raised.exception.category, "network_error")
        self.assertNotIn(TEST_API_KEY, str(raised.exception))
        self.assertNotIn(TEST_API_KEY, repr(raised.exception))

    def test_timeout_is_a_safe_distinct_failure(self):
        def handler(request):
            raise httpx.ReadTimeout("raw timeout detail", request=request)

        client = OpenAICompatibleClient(
            self.config(),
            transport=httpx.MockTransport(handler),
        )
        with self.assertRaises(LLMClientError) as raised:
            client.complete(
                [{"role": "user", "content": "context"}],
                response_format=AGENT_ACTION_RESPONSE_FORMAT,
            )
        self.assertEqual(raised.exception.category, "timeout")
        self.assertNotIn("raw timeout", str(raised.exception))

    def test_provider_http_body_and_oversized_response_are_not_exposed(self):
        cases = (
            (
                lambda _request: httpx.Response(
                    500,
                    text=f"provider secret {TEST_API_KEY}",
                ),
                "provider_http_error",
            ),
            (
                lambda _request: httpx.Response(
                    200,
                    text="X" * 2000,
                ),
                "response_too_large",
            ),
        )
        for handler, category in cases:
            with self.subTest(category=category):
                client = OpenAICompatibleClient(
                    self.config(max_response_bytes=1024),
                    transport=httpx.MockTransport(handler),
                )
                with self.assertRaises(LLMClientError) as raised:
                    client.complete(
                        [{"role": "user", "content": "context"}],
                        response_format=AGENT_ACTION_RESPONSE_FORMAT,
                    )
                self.assertEqual(raised.exception.category, category)
                self.assertNotIn(TEST_API_KEY, str(raised.exception))


def _confirmed_command(_finding, *, session=None) -> ValidationResult:
    del session
    return ValidationResult(
        status=ValidationStatus.CONFIRMED,
        confidence=0.9,
        validator="generic_http_command_execution",
        method="test-controlled deterministic validation",
        evidence={"decision": "confirmed"},
    )


class LLMPlannerOrchestrationTests(unittest.TestCase):
    def test_command_execution_runs_when_authorized_with_prerequisite(self):
        state = _state(findings=[_command_finding()])
        state = replace(
            state,
            capabilities=("unauthenticated", "application_compromise"),
        )
        content = _action_content(
            tool_id="validate-command-execution-simulation",
            finding_id="finding-command",
            expected_capabilities=["application_compromise"],
        )
        planner = LLMPlanner(
            FakeCompletionClient([content, COMPLETE_CONTENT])
        )

        with patch(
            "app.agent.executor.dispatch",
            side_effect=_confirmed_command,
        ) as deterministic_dispatch:
            final = _runtime(planner).run(state, session=object())

        deterministic_dispatch.assert_called_once()
        self.assertEqual(final.status, AgentStatus.COMPLETED)
        self.assertEqual(final.terminal_reason, "planner_completed")
        self.assertEqual(
            final.finding_by_id("finding-command").validation_status,
            "confirmed",
        )

    def test_command_execution_denied_when_unauthorized(self):
        state = _state(findings=[_command_finding()])
        state = replace(
            state,
            authorized=False,
            capabilities=("unauthenticated", "application_compromise"),
        )
        content = _action_content(
            tool_id="validate-command-execution-simulation",
            finding_id="finding-command",
            expected_capabilities=["application_compromise"],
        )
        planner = LLMPlanner(FakeCompletionClient([content]))

        with patch("app.agent.executor.dispatch") as deterministic_dispatch:
            final = _runtime(planner).run(state, session=object())

        deterministic_dispatch.assert_not_called()
        self.assertEqual(final.status, AgentStatus.BLOCKED)
        self.assertEqual(final.terminal_reason, "denied_unauthorized")

    def test_deterministic_validator_remains_source_of_truth(self):
        client = FakeCompletionClient([_action_content(), COMPLETE_CONTENT])
        planner = LLMPlanner(client)
        session = BenignScopedSession()

        final = _runtime(planner).run(_state(), session=session)

        validated = final.finding_by_id(FINDING_ID)
        self.assertEqual(final.status, AgentStatus.COMPLETED)
        self.assertEqual(validated.validation_status, "manual_review")
        self.assertNotIn("potential_information_exposure", final.capabilities)
        self.assertEqual(session.urls, [f"{ORIGIN}/debug/config"])


if __name__ == "__main__":
    unittest.main()
