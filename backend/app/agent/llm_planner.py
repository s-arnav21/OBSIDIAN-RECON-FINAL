"""Strict provider-independent LLM planner for registered agent actions."""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping, Optional, Protocol, Sequence

from app.agent.llm_client import LLMClientError
from app.agent.models import AgentAction


MAX_PLANNER_PROMPT_BYTES = 128 * 1024
MAX_PLANNER_CONTENT_BYTES = 64 * 1024
MAX_PLANNER_TOOLS = 32
MAX_PLANNER_FINDINGS = 100

SYSTEM_INSTRUCTION = """You are the autonomous operator for an authorized Obsidian Recon assessment.
Select exactly one registered tool for one in-scope finding, or decide the work is complete.
You may attach targeting options to an action, choosing from the keys a tool advertises in allowed_options (endpoint, http_method, parameter_name, parameter_location). Endpoint options must stay on the trusted origin or be a relative path.
You are not a payload author: deterministic validators always craft the exploit requests. You control where and how a finding is probed, never the payload itself.
You may iterate from prior observations: an inconclusive result may be retried on the same finding with different targeting options to drive the attack chain forward, but repeating an identical action is a duplicate and will be denied.
Preserve the supplied scan, asset, target, finding, capability, and technique identifiers.
Return only JSON: either {"decision":"action","action":{...}} or {"decision":"complete","action":null}. Do not return analysis or hidden reasoning.
Deterministic policy and validators independently decide whether an action is permitted and what its validation status is."""

_STATE_FIELDS = (
    "scan_id",
    "target",
    "asset_id",
    "authorized",
    "scan_exists",
    "validation_states",
    "capabilities",
    "mitre_techniques",
    "attack_chain_ids",
    "executed_action_ids",
    "current_step",
    "maximum_steps",
    "status",
    "terminal_reason",
)
_FINDING_FIELDS = (
    "finding_id",
    "scan_id",
    "asset_id",
    "target",
    "vulnerability_type",
    "severity",
    "validator_id",
    "endpoint",
    "http_method",
    "parameter_name",
    "parameter_location",
    "validation_status",
    "validation_confidence",
    "mitre_technique_id",
    "mitre_technique_name",
    "mitre_tactic",
    "requires_all",
    "requires_any",
    "provides",
)
_OBSERVATION_FIELDS = (
    "action_id",
    "tool_id",
    "finding_id",
    "policy_decision",
    "policy_allowed",
    "execution_status",
    "validation_status",
    "capabilities_gained",
    "summary",
    "error_category",
    "validation_decision",
    "detection_methods",
    "observed_http_status",
    "observed_response_length",
    "waf_or_filter_interference",
    "options_used",
)
_TOOL_FIELDS = (
    "tool_id",
    "validator_id",
    "vulnerability_types",
    "description",
    "requires_all",
    "requires_any",
    "provides",
    "automatic_allowed",
    "allowed_options",
)

# Ollama does not support json_schema/strict; use json_object and parse manually.
AGENT_ACTION_RESPONSE_FORMAT: Dict[str, Any] = {"type": "json_object"}


class PlannerCompletionClient(Protocol):
    def complete(
        self,
        messages: Sequence[Dict[str, str]],
        *,
        response_format: Dict[str, Any],
    ) -> str:
        ...


class LLMPlanningError(RuntimeError):
    """A safe parse/provider error suitable for fail-closed orchestration."""

    _MESSAGES = {
        "invalid_context": "The trusted planner context is invalid.",
        "prompt_too_large": "The planner context exceeded its size limit.",
        "provider_failure": "The configured planner provider failed safely.",
        "provider_timeout": "The configured planner provider timed out.",
        "invalid_json": "The planner returned invalid JSON.",
        "invalid_schema": "The planner response did not match AgentAction schema.",
        "unknown_tool": "The planner selected an unknown tool.",
        "invalid_reference": "The planner changed trusted scan context.",
    }

    def __init__(self, category: str) -> None:
        if category not in self._MESSAGES:
            category = "provider_failure"
        self.category = category
        super().__init__(self._MESSAGES[category])

    def __repr__(self) -> str:
        return f"{type(self).__name__}(category={self.category!r})"


class _DuplicateJSONKeyError(ValueError):
    pass


def _strict_json_object(pairs: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise _DuplicateJSONKeyError
        parsed[key] = value
    return parsed


def _reject_nonstandard_json_constant(_value: str) -> None:
    raise ValueError


def _project_mapping(
    value: Any,
    fields: Sequence[str],
    *,
    category: str = "invalid_context",
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LLMPlanningError(category)
    return {field: value[field] for field in fields if field in value}


def _sanitized_context(
    state: Dict[str, Any],
    available_tools: Sequence[Dict[str, Any]],
) -> tuple[Dict[str, Any], list[Dict[str, Any]]]:
    if not isinstance(state, dict) or isinstance(
        available_tools,
        (str, bytes),
    ):
        raise LLMPlanningError("invalid_context")

    required_state = {"scan_id", "asset_id", "target", "findings"}
    if not required_state.issubset(state):
        raise LLMPlanningError("invalid_context")
    findings_value = state.get("findings")
    observations_value = state.get("observations", [])
    if (
        not isinstance(findings_value, (list, tuple))
        or len(findings_value) > MAX_PLANNER_FINDINGS
        or not isinstance(observations_value, (list, tuple))
    ):
        raise LLMPlanningError("invalid_context")
    try:
        tools_value = tuple(available_tools)
    except TypeError:
        raise LLMPlanningError("invalid_context") from None
    if len(tools_value) > MAX_PLANNER_TOOLS:
        raise LLMPlanningError("invalid_context")

    projected_state = _project_mapping(state, _STATE_FIELDS)
    projected_state["findings"] = [
        _project_mapping(finding, _FINDING_FIELDS)
        for finding in findings_value
    ]
    projected_state["observations"] = [
        _project_mapping(observation, _OBSERVATION_FIELDS)
        for observation in observations_value
    ]
    projected_tools = [
        _project_mapping(tool, _TOOL_FIELDS) for tool in tools_value
    ]
    return projected_state, projected_tools


def _validate_action_references(
    action: AgentAction,
    state: Dict[str, Any],
    available_tools: Sequence[Dict[str, Any]],
) -> None:
    tool_ids = {
        tool.get("tool_id")
        for tool in available_tools
        if isinstance(tool, dict)
    }
    if action.tool_id not in tool_ids:
        raise LLMPlanningError("unknown_tool")
    if (
        action.scan_id != state.get("scan_id")
        or action.asset_id != state.get("asset_id")
        or action.target != state.get("target")
    ):
        raise LLMPlanningError("invalid_reference")

    finding = next(
        (
            candidate
            for candidate in state.get("findings", [])
            if isinstance(candidate, dict)
            and candidate.get("finding_id") == action.finding_id
        ),
        None,
    )
    if finding is None:
        raise LLMPlanningError("invalid_reference")
    if (
        finding.get("scan_id") != action.scan_id
        or finding.get("asset_id") != action.asset_id
        or finding.get("target") != action.target
    ):
        raise LLMPlanningError("invalid_reference")


def parse_planner_content(
    content: str,
    *,
    state: Dict[str, Any],
    available_tools: Sequence[Dict[str, Any]],
) -> Optional[AgentAction]:
    """Parse untrusted model output into the existing strict action contract."""
    if not isinstance(content, str):
        raise LLMPlanningError("invalid_schema")
    try:
        content_size = len(content.encode("utf-8"))
    except UnicodeError:
        raise LLMPlanningError("invalid_schema") from None
    if content_size > MAX_PLANNER_CONTENT_BYTES:
        raise LLMPlanningError("invalid_schema")
    try:
        payload = json.loads(
            content,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except _DuplicateJSONKeyError:
        raise LLMPlanningError("invalid_schema") from None
    except (json.JSONDecodeError, UnicodeError, ValueError):
        raise LLMPlanningError("invalid_json") from None
    if not isinstance(payload, dict) or set(payload) != {"decision", "action"}:
        raise LLMPlanningError("invalid_schema")

    decision = payload.get("decision")
    action_data = payload.get("action")
    if decision == "complete":
        if action_data is not None:
            raise LLMPlanningError("invalid_schema")
        return None
    if decision != "action" or not isinstance(action_data, dict):
        raise LLMPlanningError("invalid_schema")
    try:
        action = AgentAction.from_dict(action_data)
    except (TypeError, ValueError):
        raise LLMPlanningError("invalid_schema") from None
    _validate_action_references(action, state, available_tools)
    return action


class LLMPlanner:
    """Use an untrusted model only to select a registered AgentAction."""

    def __init__(self, client: PlannerCompletionClient) -> None:
        if not callable(getattr(client, "complete", None)):
            raise TypeError("client must implement complete")
        self.client = client

    def propose_action(
        self,
        state: Dict[str, Any],
        available_tools: Sequence[Dict[str, Any]],
    ) -> Optional[AgentAction]:
        safe_state, safe_tools = _sanitized_context(state, available_tools)
        try:
            user_payload = json.dumps(
                {"state": safe_state, "available_tools": safe_tools},
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            raise LLMPlanningError("invalid_context") from None
        if len(user_payload.encode("utf-8")) > MAX_PLANNER_PROMPT_BYTES:
            raise LLMPlanningError("prompt_too_large")
        messages = (
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_payload},
        )
        try:
            content = self.client.complete(
                messages,
                response_format=AGENT_ACTION_RESPONSE_FORMAT,
            )
        except LLMClientError as exc:
            category = (
                "provider_timeout"
                if exc.category == "timeout"
                else "provider_failure"
            )
            raise LLMPlanningError(category) from None
        except Exception:
            raise LLMPlanningError("provider_failure") from None
        return parse_planner_content(
            content,
            state=safe_state,
            available_tools=safe_tools,
        )
