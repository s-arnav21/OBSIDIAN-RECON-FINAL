"""Deterministic policy gate for every agent-selected action."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from app.agent.models import AgentAction, AgentState, AgentStatus
from app.agent.tools import (
    AgentToolRegistry,
    UnknownAgentToolError,
    normalize_vulnerability_type,
)
from app.scanning.scope import ReconScopeError, normalize_origin


class PolicyDecisionCode:
    ALLOWED = "allowed"
    DENIED_MISSING_SCAN = "denied_missing_scan"
    DENIED_UNAUTHORIZED = "denied_unauthorized"
    DENIED_UNKNOWN_TOOL = "denied_unknown_tool"
    DENIED_SCOPE = "denied_scope"
    DENIED_WRONG_FINDING = "denied_wrong_finding"
    DENIED_INCOMPATIBLE_TOOL = "denied_incompatible_tool"
    DENIED_OPTIONS = "denied_options"
    DENIED_PREREQUISITE = "denied_prerequisite"
    DENIED_DUPLICATE = "denied_duplicate"
    DENIED_STEP_LIMIT = "denied_step_limit"
    DENIED_NOT_AUTOMATIC = "denied_not_automatic"
    DENIED_INACTIVE_STATE = "denied_inactive_state"


@dataclass(frozen=True)
class PolicyDecision:
    action_id: str
    tool_id: str
    finding_id: str
    allowed: bool
    code: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def _decision(
    action: AgentAction,
    *,
    allowed: bool,
    code: str,
    reason: str,
) -> PolicyDecision:
    return PolicyDecision(
        action_id=action.action_id,
        tool_id=action.tool_id,
        finding_id=action.finding_id,
        allowed=allowed,
        code=code,
        reason=reason,
    )


def _same_origin(left: str, right: str) -> bool:
    try:
        return normalize_origin(left).origin == normalize_origin(right).origin
    except ReconScopeError:
        return False


def _option_endpoint_in_scope(endpoint: str, target: str) -> bool:
    """Absolute option endpoints must match the trusted origin; relative paths inherit it."""
    from urllib.parse import urlsplit

    parts = urlsplit(endpoint)
    if not (parts.scheme or parts.netloc):
        return True
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return False
    try:
        endpoint_origin = normalize_origin(
            f"{parts.scheme}://{parts.netloc}"
        ).origin
        target_origin = normalize_origin(target).origin
    except ReconScopeError:
        return False
    return endpoint_origin == target_origin


class AgentPolicyGate:
    """Fail-closed checks that cannot be bypassed by a planner."""

    def __init__(self, registry: AgentToolRegistry) -> None:
        if not isinstance(registry, AgentToolRegistry):
            raise TypeError("registry must be an AgentToolRegistry")
        self.registry = registry

    def evaluate(
        self,
        action: AgentAction,
        state: AgentState,
    ) -> PolicyDecision:
        if not isinstance(action, AgentAction):
            raise TypeError("policy requires an AgentAction")
        if not isinstance(state, AgentState):
            raise TypeError("policy requires an AgentState")
        if not state.scan_exists:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_MISSING_SCAN,
                reason="The trusted scan context does not exist.",
            )
        if not state.authorized:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_UNAUTHORIZED,
                reason="The scan is not authorized for active validation.",
            )
        if state.status not in {AgentStatus.READY, AgentStatus.RUNNING}:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_INACTIVE_STATE,
                reason="The agent state is already terminal.",
            )
        if state.current_step >= state.maximum_steps:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_STEP_LIMIT,
                reason="The configured agent step limit was reached.",
            )
        if action.scan_id != state.scan_id:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_SCOPE,
                reason="The action references a different scan.",
            )
        if action.asset_id != state.asset_id or not _same_origin(
            action.target,
            state.target,
        ):
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_SCOPE,
                reason="The action is outside the trusted asset or exact origin.",
            )
        finding = state.finding_by_id(action.finding_id)
        if finding is None:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_WRONG_FINDING,
                reason="The action references a finding unavailable to this agent.",
            )
        if (
            finding.scan_id != state.scan_id
            or finding.asset_id != state.asset_id
            or not _same_origin(finding.target, state.target)
        ):
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_WRONG_FINDING,
                reason="The finding does not belong to the trusted scan context.",
            )
        try:
            tool = self.registry.require(action.tool_id)
        except UnknownAgentToolError:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_UNKNOWN_TOOL,
                reason="The requested tool is not registered.",
            )
        effective_validator = finding.validator_id or finding.template_id
        compatible_type = normalize_vulnerability_type(
            finding.vulnerability_type
        ) in tool.vulnerability_types
        if tool.validator_id is None:
            # Real external tool: only the vulnerability type must match.
            validator_match = True
        else:
            validator_match = effective_validator == tool.validator_id
        if not validator_match or not compatible_type:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_INCOMPATIBLE_TOOL,
                reason="The tool is not compatible with the selected finding.",
            )
        for key, value in action.options:
            if key not in tool.allowed_options:
                return _decision(
                    action,
                    allowed=False,
                    code=PolicyDecisionCode.DENIED_OPTIONS,
                    reason=(
                        f"Tool {tool.tool_id!r} does not allow the {key!r} "
                        "targeting option."
                    ),
                )
            if key == "endpoint" and not _option_endpoint_in_scope(
                value,
                state.target,
            ):
                return _decision(
                    action,
                    allowed=False,
                    code=PolicyDecisionCode.DENIED_OPTIONS,
                    reason="The endpoint option is outside the trusted origin.",
                )
        if not tool.automatic_allowed:
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_NOT_AUTOMATIC,
                reason="The tool is not approved for automatic agent execution.",
            )
        if (
            action.action_id in state.executed_action_ids
            or (action.tool_id, action.finding_id, action.options_key)
            in state.executed_tool_findings
        ):
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_DUPLICATE,
                reason="This validation action has already been executed.",
            )
        available = set(state.capabilities)
        if not set(action.expected_capabilities).issubset(available):
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_PREREQUISITE,
                reason="The action was proposed against unavailable capabilities.",
            )
        all_groups = (set(tool.requires_all), set(finding.effective_requires_all))
        if any(not group.issubset(available) for group in all_groups):
            return _decision(
                action,
                allowed=False,
                code=PolicyDecisionCode.DENIED_PREREQUISITE,
                reason="Required capabilities have not been established.",
            )
        for group in (tool.requires_any, tuple(finding.effective_requires_any)):
            if group and not (set(group) & available):
                return _decision(
                    action,
                    allowed=False,
                    code=PolicyDecisionCode.DENIED_PREREQUISITE,
                    reason="No alternative prerequisite capability is available.",
                )
        return _decision(
            action,
            allowed=True,
            code=PolicyDecisionCode.ALLOWED,
            reason="The action passed all deterministic policy checks.",
        )
