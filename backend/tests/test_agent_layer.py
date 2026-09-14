"""Deterministic tests for the provider-independent bounded agent layer."""

from __future__ import annotations

import unittest
from dataclasses import replace

from app.agent.executor import AgentToolExecutor
from app.agent.models import (
    ABSOLUTE_MAX_AGENT_STEPS,
    AgentAction,
    AgentExecutionStatus,
    AgentObservation,
    AgentState,
    AgentStatus,
)
from app.agent.orchestrator import AgentOrchestrator
from app.agent.policy import AgentPolicyGate, PolicyDecisionCode
from app.agent.tools import AgentToolRegistry, UnknownAgentToolError
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult


ORIGIN = "http://127.0.0.1:8090"
SCAN_ID = "scan-agent-1"
ASSET_ID = "asset-agent-1"


def reachability_finding() -> Finding:
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


def exposure_finding(identifier: str = "finding-exposure") -> Finding:
    return Finding(
        finding_id=identifier,
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
        evidence={
            "api_key": "must-never-reach-planner",
            "raw_scanner_output": "X" * 20_000,
        },
        evidence_refs=["https://private.invalid/evidence"],
        http_request_context={
            "header": {"Authorization": "must-never-reach-planner"},
        },
    )


def command_finding() -> Finding:
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


def system_information_finding() -> Finding:
    return Finding(
        finding_id="finding-system-information",
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        target=ORIGIN,
        host="127.0.0.1",
        source="controlled_fixture",
        vulnerability_type="system_information_discovery",
        validator_id="controlled-http-system-information-discovery",
        endpoint="/admin/system-information",
        http_method="POST",
        parameter_name="discovery_token",
        parameter_location="form",
    )


def agent_state(
    *,
    findings=None,
    authorized=True,
    scan_exists=True,
    maximum_steps=5,
) -> AgentState:
    return AgentState.from_findings(
        scan_id=SCAN_ID,
        target=ORIGIN,
        asset_id=ASSET_ID,
        authorized=authorized,
        scan_exists=scan_exists,
        findings=(
            [reachability_finding(), exposure_finding()]
            if findings is None
            else findings
        ),
        maximum_steps=maximum_steps,
        attack_chain_ids=("AC-EXISTING",),
    )


def action(
    *,
    action_id="action-1",
    tool_id="validate-exposed-resource",
    scan_id=SCAN_ID,
    asset_id=ASSET_ID,
    finding_id="finding-exposure",
    target=ORIGIN,
    expected_capabilities=(),
    options=(),
) -> AgentAction:
    return AgentAction(
        action_id=action_id,
        tool_id=tool_id,
        scan_id=scan_id,
        asset_id=asset_id,
        finding_id=finding_id,
        target=target,
        reason="Validate the normalized candidate using a registered tool.",
        expected_capabilities=expected_capabilities,
        options=options,
    )


class Response:
    status_code = 200
    text = "API_KEY=test-value\nPASSWORD=test-value\n"
    headers = {"content-type": "text/plain"}


class ScopedSession:
    def __init__(self):
        self.urls = []

    def get(self, url, **_kwargs):
        self.urls.append(url)
        return Response()


class QueuePlanner:
    def __init__(self, proposals):
        self.proposals = list(proposals)
        self.states = []
        self.catalogs = []

    def propose_action(self, state, available_tools):
        self.states.append(state)
        self.catalogs.append(available_tools)
        return self.proposals.pop(0) if self.proposals else None


class RepeatingPlanner:
    def __init__(self):
        self.count = 0

    def propose_action(self, _state, _available_tools):
        self.count += 1
        return action(action_id=f"repeat-{self.count}")


def runtime(planner):
    registry = AgentToolRegistry()
    policy = AgentPolicyGate(registry)
    executor = AgentToolExecutor(registry, policy)
    return AgentOrchestrator(
        registry=registry,
        executor=executor,
        planner=planner,
    )


class AgentContractTests(unittest.TestCase):
    def test_state_construction_derives_compact_security_context(self):
        state = agent_state()
        self.assertEqual(state.status, AgentStatus.READY)
        self.assertIn("unauthenticated", state.capabilities)
        self.assertIn("discovered_services", state.capabilities)
        self.assertEqual(state.attack_chain_ids, ("AC-EXISTING",))
        self.assertEqual(
            state.to_dict()["validation_states"]["finding-exposure"],
            "detected",
        )

    def test_state_serialization_excludes_evidence_request_state_and_secrets(self):
        serialized = agent_state().to_dict()
        text = str(serialized)
        self.assertNotIn("must-never-reach-planner", text)
        self.assertNotIn("raw_scanner_output", text)
        self.assertNotIn("evidence", serialized["findings"][1])
        self.assertNotIn("evidence_refs", serialized["findings"][1])
        self.assertNotIn("http_request_context", serialized["findings"][1])

    def test_state_rejects_cross_scan_asset_and_target_findings(self):
        base = exposure_finding()
        invalid = (
            replace(base, scan_id="scan-other"),
            replace(base, asset_id="asset-other"),
            replace(base, target="http://127.0.0.1:9090"),
        )
        for finding in invalid:
            with self.subTest(finding=finding), self.assertRaises(ValueError):
                agent_state(findings=[finding])

    def test_step_bound_is_hard_limited(self):
        with self.assertRaises(ValueError):
            agent_state(maximum_steps=ABSOLUTE_MAX_AGENT_STEPS + 1)

    def test_action_round_trip_is_strict(self):
        original = action(expected_capabilities=("discovered_services",))
        restored = AgentAction.from_dict(original.to_dict())
        self.assertEqual(restored, original)

    def test_action_rejects_arbitrary_command_payload_and_url_fields(self):
        data = action().to_dict()
        for field_name in ("command", "payload", "scanner_flags", "url"):
            with self.subTest(field_name=field_name):
                malicious = {**data, field_name: "attacker-controlled"}
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    AgentAction.from_dict(malicious)

    def test_observation_is_bounded_and_validates_status(self):
        observation = AgentObservation(
            action_id="a",
            tool_id="t",
            finding_id="f",
            policy_decision="allowed",
            policy_allowed=True,
            execution_status="completed",
            validation_status="confirmed",
            summary="Deterministic validation completed.",
            capabilities_gained=("application_compromise",),
        )
        self.assertEqual(observation.to_dict()["validation_status"], "confirmed")
        with self.assertRaises(ValueError):
            replace(observation, summary="X" * 513)


class AgentToolRegistryTests(unittest.TestCase):
    def test_registry_discovers_only_fixed_validator_backed_tools(self):
        registry = AgentToolRegistry()
        tools = registry.list_tools()
        self.assertEqual(len(tools), 6)
        self.assertEqual(
            {tool.validator_id for tool in tools},
            {
                "generic-http-sqli",
                "generic-http-reflected-xss",
                "generic-http-ssrf",
                "generic-http-exposed-resource",
                "generic-http-command-execution",
                "controlled-http-system-information-discovery",
            },
        )
        self.assertNotIn("dvwa-sqli-low", str(registry.planner_catalog()))
        self.assertNotIn("handler", str(registry.planner_catalog()))

    def test_registry_rejects_unknown_tools(self):
        with self.assertRaises(UnknownAgentToolError):
            AgentToolRegistry().require("shell")

    def test_command_simulation_is_visible_and_automatic_for_capstone(self):
        tool = AgentToolRegistry().require(
            "validate-command-execution-simulation"
        )
        self.assertTrue(tool.automatic_allowed)

    def test_system_information_simulation_is_automatic_with_prerequisite(self):
        tool = AgentToolRegistry().require(
            "validate-system-information-discovery-simulation"
        )
        self.assertEqual(tool.requires_any, ("command_execution",))
        self.assertEqual(tool.provides, ("system_information",))
        self.assertTrue(tool.automatic_allowed)


class AgentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.registry = AgentToolRegistry()
        self.policy = AgentPolicyGate(self.registry)
        self.state = agent_state()

    def assert_decision(self, requested, code, allowed=False):
        decision = self.policy.evaluate(requested, self.state)
        self.assertEqual(decision.code, code)
        self.assertEqual(decision.allowed, allowed)
        return decision

    def test_valid_action_is_approved(self):
        self.assert_decision(action(), PolicyDecisionCode.ALLOWED, True)

    def test_unknown_tool_is_denied(self):
        self.assert_decision(
            action(tool_id="arbitrary-shell"),
            PolicyDecisionCode.DENIED_UNKNOWN_TOOL,
        )

    def test_wrong_finding_and_tool_compatibility_are_denied(self):
        self.assert_decision(
            action(finding_id="finding-missing"),
            PolicyDecisionCode.DENIED_WRONG_FINDING,
        )
        self.assert_decision(
            action(tool_id="validate-reflected-xss"),
            PolicyDecisionCode.DENIED_INCOMPATIBLE_TOOL,
        )

    def test_cross_scan_asset_and_origin_are_denied(self):
        variants = (
            action(scan_id="scan-other"),
            action(asset_id="asset-other"),
            action(target="http://127.0.0.1:9090"),
            action(target="not-a-url"),
        )
        for requested in variants:
            with self.subTest(requested=requested):
                self.assert_decision(
                    requested,
                    PolicyDecisionCode.DENIED_SCOPE,
                )

    def test_missing_or_unauthorized_scan_is_denied(self):
        for state, code in (
            (
                agent_state(scan_exists=False),
                PolicyDecisionCode.DENIED_MISSING_SCAN,
            ),
            (
                agent_state(authorized=False),
                PolicyDecisionCode.DENIED_UNAUTHORIZED,
            ),
        ):
            with self.subTest(code=code):
                self.state = state
                self.assert_decision(action(), code)

    def test_prerequisite_and_stale_expected_capability_are_denied(self):
        self.state = agent_state(findings=[exposure_finding()])
        self.assert_decision(
            action(),
            PolicyDecisionCode.DENIED_PREREQUISITE,
        )
        self.state = agent_state()
        self.assert_decision(
            action(expected_capabilities=("application_compromise",)),
            PolicyDecisionCode.DENIED_PREREQUISITE,
        )

    def test_duplicate_action_id_or_tool_finding_pair_is_denied(self):
        self.state = replace(
            self.state,
            executed_action_ids=("action-1",),
        )
        self.assert_decision(action(), PolicyDecisionCode.DENIED_DUPLICATE)

        prior = AgentObservation(
            action_id="prior-action",
            tool_id="validate-exposed-resource",
            finding_id="finding-exposure",
            policy_decision="allowed",
            policy_allowed=True,
            execution_status="completed",
            validation_status="confirmed",
            summary="Completed.",
        )
        self.state = replace(
            agent_state(),
            observations=(prior,),
            executed_action_ids=("prior-action",),
        )
        self.assert_decision(
            action(action_id="new-action"),
            PolicyDecisionCode.DENIED_DUPLICATE,
        )

    def test_step_limit_is_denied(self):
        self.state = replace(self.state, current_step=self.state.maximum_steps)
        self.assert_decision(action(), PolicyDecisionCode.DENIED_STEP_LIMIT)

    def test_nonautomatic_tool_is_denied_even_with_prerequisite(self):
        command_tool = AgentToolRegistry().require(
            "validate-command-execution-simulation"
        )
        registry = AgentToolRegistry(
            [replace(command_tool, automatic_allowed=False)]
        )
        policy = AgentPolicyGate(registry)
        state = AgentState.from_findings(
            scan_id=SCAN_ID,
            target=ORIGIN,
            asset_id=ASSET_ID,
            authorized=True,
            findings=[command_finding()],
            maximum_steps=2,
        )
        state = replace(
            state,
            capabilities=("unauthenticated", "application_compromise"),
        )
        requested = action(
            tool_id="validate-command-execution-simulation",
            finding_id="finding-command",
        )
        decision = policy.evaluate(requested, state)
        self.assertEqual(
            decision.code,
            PolicyDecisionCode.DENIED_NOT_AUTOMATIC,
        )
        self.assertFalse(decision.allowed)

    def test_system_information_enforces_prerequisite_even_when_automatic(self):
        self.state = AgentState.from_findings(
            scan_id=SCAN_ID,
            target=ORIGIN,
            asset_id=ASSET_ID,
            authorized=True,
            findings=[system_information_finding()],
            maximum_steps=2,
        )
        self.state = replace(
            self.state,
            capabilities=("unauthenticated",),
        )
        requested = action(
            tool_id="validate-system-information-discovery-simulation",
            finding_id="finding-system-information",
            expected_capabilities=("command_execution",),
        )
        self.assert_decision(
            requested,
            PolicyDecisionCode.DENIED_PREREQUISITE,
        )
        self.state = replace(
            self.state,
            capabilities=("unauthenticated", "command_execution"),
        )
        self.assert_decision(
            requested,
            PolicyDecisionCode.ALLOWED,
            True,
        )


class AgentOptionTests(unittest.TestCase):
    """Bounded targeting options: allowlist, enums, origin, and dedup keying."""

    def sqli_finding(self):
        return Finding(
            finding_id="finding-sqli",
            scan_id=SCAN_ID,
            asset_id=ASSET_ID,
            target=ORIGIN,
            host="127.0.0.1",
            source="nuclei",
            vulnerability_type="sql_injection",
            validator_id="generic-http-sqli",
            endpoint="/items",
            http_method="GET",
            parameter_name="id",
            parameter_location="query",
            severity="high",
        )

    def setUp(self):
        self.registry = AgentToolRegistry()
        self.policy = AgentPolicyGate(self.registry)
        self.state = agent_state(
            findings=[reachability_finding(), self.sqli_finding()]
        )

    def optioned_action(self, **updates):
        data = dict(
            action_id="action-opted",
            tool_id="validate-sql-injection",
            finding_id="finding-sqli",
            options={
                "endpoint": "/search",
                "http_method": "POST",
                "parameter_name": "term",
                "parameter_location": "form",
            },
        )
        data.update(updates)
        return action(**data)

    def assert_decision(self, requested, code, allowed=False):
        decision = self.policy.evaluate(requested, self.state)
        self.assertEqual(decision.code, code)
        self.assertEqual(decision.allowed, allowed)
        return decision

    def test_registered_options_within_allowlist_are_approved(self):
        decision = self.policy.evaluate(self.optioned_action(), self.state)
        self.assertEqual(decision.code, PolicyDecisionCode.ALLOWED)
        self.assertTrue(decision.allowed)

    def test_same_origin_absolute_endpoint_option_is_approved(self):
        requested = self.optioned_action(options={
            "endpoint": f"{ORIGIN}/items",
        })
        decision = self.policy.evaluate(requested, self.state)
        self.assertEqual(decision.code, PolicyDecisionCode.ALLOWED)

    def test_tool_without_option_support_is_denied(self):
        requested = action(
            action_id="action-cmd-option",
            tool_id="validate-command-execution-simulation",
            finding_id="finding-command",
            options={"endpoint": "/diagnostics"},
        )
        state = agent_state(
            findings=[command_finding()],
            maximum_steps=2,
        )
        state = replace(
            state,
            capabilities=("unauthenticated", "application_compromise"),
        )
        decision = self.policy.evaluate(requested, state)
        self.assertEqual(decision.code, PolicyDecisionCode.DENIED_OPTIONS)
        self.assertFalse(decision.allowed)

    def test_enum_violating_option_is_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "http_method"):
            action(
                action_id="action-opt-enum",
                tool_id="validate-sql-injection",
                finding_id="finding-sqli",
                options={"http_method": "TRACE"},
            )

    def test_cross_origin_endpoint_option_is_denied(self):
        requested = self.optioned_action(options={
            "endpoint": "http://127.0.0.1:9999/items",
        })
        decision = self.policy.evaluate(requested, self.state)
        self.assertEqual(decision.code, PolicyDecisionCode.DENIED_OPTIONS)
        self.assertFalse(decision.allowed)

    def test_options_are_duplicate_key_and_variant_retries_are_bounded(self):
        first = self.optioned_action(
            action_id="action-sqli-a",
            options={"parameter_name": "id"},
        )
        identical = self.optioned_action(
            action_id="action-sqli-b",
            options={"parameter_name": "id"},
        )
        variant = self.optioned_action(
            action_id="action-sqli-c",
            options={"parameter_name": "term"},
        )
        self.assertEqual(first.options_key, identical.options_key)
        self.assertNotEqual(first.options_key, variant.options_key)

        prior = AgentObservation(
            action_id="action-sqli-a",
            tool_id="validate-sql-injection",
            finding_id="finding-sqli",
            policy_decision="allowed",
            policy_allowed=True,
            execution_status="completed",
            validation_status="manual_review",
            summary="Inconclusive; retry a different parameter.",
            options_used=first.options_key,
        )
        self.state = replace(
            self.state,
            observations=(prior,),
            executed_action_ids=("action-sqli-a",),
        )
        self.assert_decision(
            identical,
            PolicyDecisionCode.DENIED_DUPLICATE,
        )
        self.assert_decision(variant, PolicyDecisionCode.ALLOWED, True)

    def test_unknown_option_key_is_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "unsupported agent action option"):
            AgentAction.from_dict({
                **action(tool_id="validate-sql-injection",
                         finding_id="finding-sqli").to_dict(),
                "options": {"payload": "1 OR 1=1"},
            })


class AgentExecutorTests(unittest.TestCase):
    def setUp(self):
        self.registry = AgentToolRegistry()
        self.policy = AgentPolicyGate(self.registry)
        self.executor = AgentToolExecutor(self.registry, self.policy)
        self.state = agent_state()

    def test_successful_execution_uses_existing_validator_and_observes_result(self):
        session = ScopedSession()
        result = self.executor.execute(action(), self.state, session=session)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.observation.execution_status, "completed")
        self.assertEqual(result.observation.validation_status, "confirmed")
        self.assertEqual(
            result.validation_result.validator,
            "generic_http_exposed_resource",
        )
        self.assertEqual(result.updated_finding.validation_status, "confirmed")
        self.assertEqual(
            result.observation.capabilities_gained,
            ("potential_information_exposure",),
        )
        self.assertEqual(session.urls, [f"{ORIGIN}/debug/config"])

    def test_denied_action_never_reaches_dispatcher(self):
        result = self.executor.execute(
            action(tool_id="arbitrary-command"),
            self.state,
            session=object(),
        )
        self.assertEqual(result.observation.execution_status, "blocked")
        self.assertIsNone(result.validation_result)
        self.assertIsNone(result.updated_finding)

    def test_validator_error_details_are_not_exposed_to_observation(self):
        class FailingSession:
            def get(self, _url):
                raise RuntimeError("database-password=secret")

        result = self.executor.execute(
            action(),
            self.state,
            session=FailingSession(),
        )
        serialized = str(result.observation.to_dict())
        self.assertEqual(result.observation.validation_status, "manual_review")
        self.assertEqual(
            result.observation.error_category,
            "validator_reported_error",
        )
        self.assertNotIn("database-password", serialized)
        self.assertNotIn("secret", serialized)

    def test_option_endpoint_is_applied_before_dispatch(self):
        session = ScopedSession()
        result = self.executor.execute(
            action(
                action_id="action-option",
                options={"endpoint": "/health"},
            ),
            self.state,
            session=session,
        )
        self.assertTrue(result.policy.allowed)
        self.assertEqual(session.urls, [f"{ORIGIN}/health"])

    def test_observation_carries_sanitized_reflection_evidence(self):
        session = ScopedSession()
        result = self.executor.execute(action(), self.state, session=session)
        observation = result.observation
        self.assertEqual(observation.execution_status, "completed")
        self.assertEqual(observation.validation_decision, "confirmed")
        self.assertEqual(observation.observed_http_status, 200)
        self.assertIsInstance(observation.observed_response_length, int)
        serialized = str(observation.to_dict())
        self.assertNotIn("test-value", serialized)
        self.assertNotIn("PASSWORD", serialized)


class AgentOrchestratorTests(unittest.TestCase):
    def test_fake_planner_executes_updates_state_and_completes_cleanly(self):
        planner = QueuePlanner([action(), None])
        final = runtime(planner).run(
            agent_state(maximum_steps=3),
            session=ScopedSession(),
        )
        self.assertEqual(final.status, AgentStatus.COMPLETED)
        self.assertEqual(final.terminal_reason, "planner_completed")
        self.assertEqual(final.current_step, 1)
        self.assertEqual(final.executed_action_ids, ("action-1",))
        self.assertIn("potential_information_exposure", final.capabilities)
        self.assertEqual(
            final.finding_by_id("finding-exposure").validation_status,
            "confirmed",
        )
        self.assertNotIn("must-never-reach-planner", str(planner.states))
        self.assertEqual(len(planner.catalogs[0]), 6)

    def test_policy_denial_blocks_orchestration(self):
        planner = QueuePlanner([action(tool_id="unknown-agent-tool")])
        final = runtime(planner).run(agent_state(), session=ScopedSession())
        self.assertEqual(final.status, AgentStatus.BLOCKED)
        self.assertEqual(final.terminal_reason, "denied_unknown_tool")
        self.assertEqual(final.observations[-1].execution_status, "blocked")

    def test_duplicate_tool_finding_terminates_deterministically(self):
        final = runtime(RepeatingPlanner()).run(
            agent_state(maximum_steps=3),
            session=ScopedSession(),
        )
        self.assertEqual(final.status, AgentStatus.BLOCKED)
        self.assertEqual(final.terminal_reason, "denied_duplicate")
        self.assertEqual(final.current_step, 2)
        self.assertEqual(final.executed_action_ids, ("repeat-1",))

    def test_maximum_step_limit_stops_without_an_extra_planner_call(self):
        second = exposure_finding("finding-exposure-2")
        planner = QueuePlanner([
            action(action_id="a1"),
            action(action_id="a2", finding_id="finding-exposure-2"),
            None,
        ])
        final = runtime(planner).run(
            agent_state(
                findings=[reachability_finding(), exposure_finding(), second],
                maximum_steps=2,
            ),
            session=ScopedSession(),
        )
        self.assertEqual(final.status, AgentStatus.BLOCKED)
        self.assertEqual(final.terminal_reason, "step_limit_reached")
        self.assertEqual(final.current_step, 2)
        self.assertEqual(len(planner.states), 2)

    def test_planner_cannot_directly_set_validation_confirmation(self):
        fake_confirmation = ValidationResult(
            status="confirmed",
            confidence=1.0,
            validator="planner",
            method="fabricated",
        )
        final = runtime(QueuePlanner([fake_confirmation])).run(agent_state())
        self.assertEqual(final.status, AgentStatus.FAILED)
        self.assertEqual(final.terminal_reason, "invalid_planner_output")
        self.assertEqual(
            final.finding_by_id("finding-exposure").validation_status,
            "detected",
        )
        self.assertEqual(final.executed_action_ids, ())

    def test_planner_exception_fails_without_leaking_exception(self):
        class FailingPlanner:
            def propose_action(self, _state, _tools):
                raise RuntimeError("api-key=secret")

        final = runtime(FailingPlanner()).run(agent_state())
        self.assertEqual(final.status, AgentStatus.FAILED)
        self.assertEqual(final.terminal_reason, "planner_error")
        self.assertNotIn("secret", str(final.to_dict()))


if __name__ == "__main__":
    unittest.main()
