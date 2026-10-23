"""Installed real tools must be visible to the LLM planner and executable.

The planner only advertises tools the environment can actually run, so that the
LLM never selects an unavailable binary. These tests prove the agent wiring
end-to-end for every external tool whose binary is present:

  * it appears in the planner catalog (``get_available_tool_catalog``),
  * it advertises the planner-supplied targeting options,
  * an LLM-shaped action selecting it passes the deterministic policy gate, and
  * the executor dispatches it with a resolved, same-origin target.

Cases whose binary is absent are skipped, so the suite still passes on a host
without the full toolchain (for example a build that omits Metasploit).
"""

from __future__ import annotations

import json
import unittest
from typing import Any, Dict, Sequence
from unittest import mock

from app.agent.executor import AgentToolExecutor
from app.agent.llm_client import _chat_endpoint
from app.agent.llm_planner import LLMPlanner
from app.agent.models import AgentAction, AgentExecutionStatus, AgentState
from app.agent.policy import AgentPolicyGate
from app.agent.tools import (
    AgentToolRegistry,
    TOOL_REGISTRY,
    ToolResult,
    _binary_available,
    get_available_tool_catalog,
    get_tool_catalog,
)
from app.models.finding import Finding, ValidationStatus

ORIGIN = "http://127.0.0.1:8090"
SCAN_ID = "scan-real-tools"
ASSET_ID = "asset-real-tools"

_DEFAULT_ALLOWED = (
    "endpoint",
    "http_method",
    "parameter_name",
    "parameter_location",
)

# tool_id -> the vulnerability type its finding must carry to be compatible.
_REAL_TOOL_CASES = {
    "sqlmap-exploit": "sql-injection",
    "gobuster-dir": "exposed-admin-panel",
    "ffuf-fuzz": "exposed-admin-panel",
    "katana-crawl": "discovered-path",
    "nikto-scan": "misconfiguration",
    "hydra-brute": "default-credentials",
    "nmap-vuln-scripts": "open-service-exposure",
}


def _finding(finding_id: str, vulnerability_type: str) -> Finding:
    return Finding(
        finding_id=finding_id,
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        target=ORIGIN,
        host="127.0.0.1",
        source="test",
        vulnerability_type=vulnerability_type,
        endpoint="/items?id=1",
        http_method="GET",
        parameter_name="id",
        parameter_location="query",
        severity="high",
        validation_status=ValidationStatus.CONFIRMED,
        validation_confidence=1.0,
    )


def _state(finding: Finding) -> AgentState:
    return AgentState.from_findings(
        scan_id=SCAN_ID,
        target=ORIGIN,
        asset_id=ASSET_ID,
        authorized=True,
        findings=[finding],
        maximum_steps=3,
    )


def _action(tool_id: str, finding_id: str) -> AgentAction:
    """An action shaped exactly like one the LLM planner would emit."""
    return AgentAction(
        action_id=f"action-{tool_id}",
        tool_id=tool_id,
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        finding_id=finding_id,
        target=ORIGIN,
        reason="planner selected an external tool for this finding",
        expected_capabilities=(),
        options=(
            ("endpoint", "/items"),
            ("http_method", "GET"),
            ("parameter_name", "id"),
            ("parameter_location", "query"),
        ),
    )


class RealToolCatalogTests(unittest.TestCase):
    def test_installed_real_tools_are_advertised_as_available(self):
        available = {tool["tool_id"] for tool in get_available_tool_catalog()}
        for tool_id in _REAL_TOOL_CASES:
            binary = TOOL_REGISTRY[tool_id].requires_binary
            if _binary_available(binary):
                self.assertIn(
                    tool_id,
                    available,
                    f"{tool_id} is installed but was not advertised to the planner",
                )

    def test_absent_binaries_are_not_offered_to_the_planner(self):
        catalog = {tool["tool_id"]: tool for tool in get_tool_catalog()}
        available = {tool["tool_id"] for tool in get_available_tool_catalog()}
        for tool_id, tool in TOOL_REGISTRY.items():
            if not tool.requires_binary:
                continue
            if _binary_available(tool.requires_binary):
                continue
            self.assertFalse(catalog[tool_id]["available"])
            self.assertNotIn(tool_id, available)

    def test_real_tools_advertise_the_targeting_options_the_llm_may_send(self):
        registry = AgentToolRegistry()
        for tool_id, tool in TOOL_REGISTRY.items():
            if tool.category.value != "real_tool":
                continue
            definition = registry.require(tool_id)
            for option in _DEFAULT_ALLOWED:
                self.assertIn(option, definition.allowed_options)


class RealToolPlannerToExecutionTests(unittest.TestCase):
    def test_llm_selected_real_tool_passes_policy_and_is_dispatched(self):
        gate = AgentPolicyGate(AgentToolRegistry())
        executor = AgentToolExecutor(AgentToolRegistry(), gate)
        exercised = 0
        for tool_id, vulnerability_type in _REAL_TOOL_CASES.items():
            binary = TOOL_REGISTRY[tool_id].requires_binary
            if not _binary_available(binary):
                continue
            exercised += 1
            with self.subTest(tool_id=tool_id):
                finding = _finding(f"finding-{tool_id}", vulnerability_type)
                state = _state(finding)
                action = _action(tool_id, finding.finding_id)

                decision = gate.evaluate(action, state)
                self.assertTrue(decision.allowed, decision.reason)

                sentinel = ToolResult(
                    tool_id=tool_id, success=True, output="ok", extra={}
                )
                with mock.patch(
                    "app.agent.executor.execute_tool", return_value=sentinel
                ) as dispatch:
                    execution = executor.execute(action, state)

                dispatch.assert_called_once()
                called_id, called_options = dispatch.call_args[0]
                self.assertEqual(called_id, tool_id)
                self.assertTrue(called_options.get("target"))
                self.assertEqual(
                    execution.observation.execution_status,
                    AgentExecutionStatus.COMPLETED,
                )
        if exercised == 0:
            self.skipTest("no external tool binaries installed in this environment")


class _StubCompletionClient:
    """Stands in for the model: records the prompt and replays fixed JSON."""

    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.messages: Sequence[Dict[str, str]] = ()

    def complete(
        self,
        messages: Sequence[Dict[str, str]],
        *,
        response_format: Dict[str, Any],
    ) -> str:
        self.messages = tuple(messages)
        return self.payload


class LLMPlannerToolSelectionTests(unittest.TestCase):
    """A model that selects a real tool must have it offered and accepted."""

    def test_model_selecting_a_real_tool_is_advertised_and_accepted(self):
        tool_id = "sqlmap-exploit"
        if not _binary_available(TOOL_REGISTRY[tool_id].requires_binary):
            self.skipTest("sqlmap not installed")
        finding = _finding("finding-sqli", "sql-injection")
        state = _state(finding)
        payload = json.dumps({
            "decision": "action",
            "action": {
                "action_id": "llm-step-1",
                "tool_id": tool_id,
                "scan_id": SCAN_ID,
                "asset_id": ASSET_ID,
                "finding_id": finding.finding_id,
                "target": ORIGIN,
                "reason": "escalate SQL injection to sqlmap",
                "expected_capabilities": [],
                "options": {"parameter_name": "id"},
            },
        })
        client = _StubCompletionClient(payload)
        action = LLMPlanner(client).propose_action(state.to_dict())

        self.assertIsNotNone(action)
        self.assertEqual(action.tool_id, tool_id)
        # The model was genuinely offered the installed tool in its catalog.
        offered = client.messages[1]["content"]
        self.assertIn(tool_id, offered)
        self.assertIn("available", offered)


class ChatEndpointTests(unittest.TestCase):
    """The planner must target the right path for the configured provider."""

    def test_openai_compatible_v1_base_uses_chat_completions(self):
        self.assertEqual(
            _chat_endpoint("http://provider.test/v1"),
            "http://provider.test/v1/chat/completions",
        )

    def test_ollama_base_uses_native_api_chat(self):
        self.assertEqual(
            _chat_endpoint("http://10.0.0.5:11434"),
            "http://10.0.0.5:11434/api/chat",
        )

    def test_explicit_chat_path_is_honoured(self):
        self.assertEqual(
            _chat_endpoint("http://host/v1/chat/completions"),
            "http://host/v1/chat/completions",
        )


if __name__ == "__main__":
    unittest.main()
