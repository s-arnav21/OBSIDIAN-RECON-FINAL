"""Technique evaluation for the shared agent policy gate.

The primary gate lives in :mod:`app.agent.policy` (``AgentPolicyGate``). It
delegates any action whose ``tool_id`` is ``technique:<Txxxx>`` to
:func:`evaluate_technique_action` here. That keeps one coherent policy gate
while letting technique scripts enforce a *strict* prerequisite graph: unlike
ordinary validator tools, a technique's ``requires_any`` must be satisfied by
capabilities that were genuinely obtained (base capabilities, the ``provides``
of confirmed findings, or capabilities granted by earlier successful
technique observations) -- never by capabilities that were merely *required*
by an unconfirmed finding.

``TechniquePolicyGate`` is a thin standalone wrapper around the shared gate,
useful for direct technique evaluation in tests and tooling.
"""

from __future__ import annotations

from typing import Any, Optional

from app.agent.models import AgentAction, AgentState
from app.attack_chain.engine import BASE_CAPABILITIES
from app.models.finding import Finding, ValidationStatus

TECHNIQUE_TOOL_PREFIX = "technique:"


class TechniquePolicyDecisionCode:
    """Decision codes, mirroring ``app.agent.policy.PolicyDecisionCode``."""

    ALLOWED = "allowed"
    DENIED_MISSING_SCAN = "denied_missing_scan"
    DENIED_UNAUTHORIZED = "denied_unauthorized"
    DENIED_UNKNOWN_TOOL = "denied_unknown_tool"
    DENIED_SCOPE = "denied_scope"
    DENIED_WRONG_FINDING = "denied_wrong_finding"
    DENIED_PREREQUISITE = "denied_prerequisite"
    DENIED_DUPLICATE = "denied_duplicate"
    DENIED_STEP_LIMIT = "denied_step_limit"
    DENIED_NOT_AUTOMATIC = "denied_not_automatic"


def _decision(
    action: AgentAction,
    *,
    allowed: bool,
    code: str,
    reason: str,
) -> Any:
    from app.agent.policy import PolicyDecision  # lazy: avoids import cycle

    return PolicyDecision(
        action_id=action.action_id,
        tool_id=action.tool_id,
        finding_id=action.finding_id,
        allowed=allowed,
        code=code,
        reason=reason,
    )


def true_capabilities(state: AgentState) -> frozenset:
    """Capabilities actually held, derived from ground truth.

    ``AgentState.from_findings`` seeds only ``BASE_CAPABILITIES`` plus the
    ``provides`` of confirmed findings. A finding's ``requires_any`` /
    ``requires_all`` are assumptions about the target, not acquired access, and
    are never treated as held capabilities.
    """
    capabilities = set(BASE_CAPABILITIES)
    for finding in state.findings:
        if finding.validation_status == ValidationStatus.CONFIRMED:
            capabilities.update(finding.provides)
    for observation in state.observations:
        capabilities.update(observation.capabilities_gained)
    return frozenset(capabilities)


def evaluate_technique_action(
    action: AgentAction,
    state: AgentState,
    finding: Optional[Finding] = None,
    *,
    allow_non_automatic: Optional[bool] = None,
) -> Optional[Any]:
    """Return a ``PolicyDecision`` for a ``technique:`` action, else ``None``.

    Assumes the caller has already validated scan/asset/origin/finding
    membership (as ``AgentPolicyGate`` does before delegating).
    """
    if not action.tool_id.startswith(TECHNIQUE_TOOL_PREFIX):
        return None

    if allow_non_automatic is None:
        try:
            from app.core.config import settings

            allow_non_automatic = settings.AUTOMATION_ALLOW_NON_AUTOMATIC
        except Exception:  # noqa: BLE001
            allow_non_automatic = False

    technique_id = action.tool_id[len(TECHNIQUE_TOOL_PREFIX):]
    from app.automation import get_technique, has_technique

    if not has_technique(technique_id):
        return _decision(
            action,
            allowed=False,
            code=TechniquePolicyDecisionCode.DENIED_UNKNOWN_TOOL,
            reason=f"unknown technique {technique_id!r}",
        )
    technique = get_technique(technique_id)

    fingerprint = (action.tool_id, action.finding_id, action.options)
    if (
        action.action_id in state.executed_action_ids
        or fingerprint in state.executed_tool_findings
    ):
        return _decision(
            action,
            allowed=False,
            code=TechniquePolicyDecisionCode.DENIED_DUPLICATE,
            reason="this exact technique action was already executed",
        )

    if not technique.automatic_allowed and not allow_non_automatic:
        return _decision(
            action,
            allowed=False,
            code=TechniquePolicyDecisionCode.DENIED_NOT_AUTOMATIC,
            reason=f"{technique.technique_id} requires explicit operator opt-in",
        )

    capabilities = true_capabilities(state)
    if technique.requires_all and not all(
        req in capabilities for req in technique.requires_all
    ):
        return _decision(
            action,
            allowed=False,
            code=TechniquePolicyDecisionCode.DENIED_PREREQUISITE,
            reason=(
                f"{technique.technique_id} requires all of "
                f"{list(technique.requires_all)}"
            ),
        )
    if technique.requires_any and not any(
        req in capabilities for req in technique.requires_any
    ):
        return _decision(
            action,
            allowed=False,
            code=TechniquePolicyDecisionCode.DENIED_PREREQUISITE,
            reason=(
                f"{technique.technique_id} needs one of "
                f"{list(technique.requires_any)}"
            ),
        )

    return _decision(
        action,
        allowed=True,
        code=TechniquePolicyDecisionCode.ALLOWED,
        reason="authorized in-scope technique with satisfied prerequisites",
    )


class TechniquePolicyGate:
    """Standalone wrapper delegating to the shared ``AgentPolicyGate``."""

    def __init__(
        self,
        registry: Any = None,
        *,
        allow_non_automatic: bool = False,
    ) -> None:
        self.registry = registry
        self.allow_non_automatic = allow_non_automatic

    def evaluate(self, action: AgentAction, state: AgentState) -> Any:
        if self.registry is None:
            from app.agent.tools import AgentToolRegistry

            registry = AgentToolRegistry()
        else:
            registry = self.registry
        from app.agent.policy import AgentPolicyGate

        return AgentPolicyGate(registry).evaluate(action, state)


__all__ = [
    "TechniquePolicyGate",
    "TechniquePolicyDecisionCode",
    "TECHNIQUE_TOOL_PREFIX",
    "evaluate_technique_action",
    "true_capabilities",
]
