"""Policy-enforced adapter from agent tools to canonical validators."""

from __future__ import annotations

from dataclasses import dataclass, replace
from numbers import Real
from typing import Any, Optional

from app.agent.models import (
    AgentAction,
    AgentExecutionStatus,
    AgentObservation,
    AgentState,
)
from app.agent.policy import AgentPolicyGate, PolicyDecision
from app.agent.tools import AgentToolRegistry
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.validation.dispatcher import apply_validation_result, dispatch


@dataclass(frozen=True)
class AgentExecution:
    observation: AgentObservation
    policy: PolicyDecision
    updated_finding: Optional[Finding] = None
    validation_result: Optional[ValidationResult] = None


def _finding_with_options(
    finding: Finding,
    options: tuple[tuple[str, str], ...],
) -> Finding:
    """Apply validated targeting options as bounded overrides to the finding."""
    overrides = {}
    for key, value in options:
        overrides[key] = value
    if not overrides:
        return finding
    return replace(finding, **overrides)


def _coerce_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _bounded_string(value: Any, maximum: int = 512) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return value if len(value) <= maximum else value[: maximum - 1] + "\u2026"


def _validation_decision(result: ValidationResult) -> Optional[str]:
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    for key in ("decision", "reason"):
        decision = _bounded_string(evidence.get(key))
        if decision is not None:
            return decision
    return _bounded_string(result.error)


def _detection_methods(result: ValidationResult) -> tuple[str, ...]:
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    methods = evidence.get("methods_triggered")
    if not isinstance(methods, (list, tuple)):
        return ()
    bounded = tuple(
        str(method).strip()[:128]
        for method in methods
        if isinstance(method, str) and method.strip()
    )
    return tuple(dict.fromkeys(bounded))[:8]


def _first_number(
    evidence: dict[str, Any],
    keys: tuple[str, ...],
) -> Optional[int]:
    for key in keys:
        value = _coerce_int(evidence.get(key))
        if value is not None:
            return value
    return None


def _observable_evidence(
    result: ValidationResult,
) -> tuple[Optional[str], tuple[str, ...], Optional[int], Optional[int], bool]:
    """Extract bounded, sanitized validator signals safe for planner feedback.

    Only scalar decision/status/length summaries are returned -- never raw
    response bodies, headers, cookies, or payload evidence.
    """
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    enforcement_keys = (
        "waf_or_filter_interference",
        "filter_interference",
    )
    waf = any(
        evidence.get(key) is True for key in enforcement_keys
    )
    http_status = _first_number(
        evidence,
        ("http_status", "status", "response_status", "baseline_http_status"),
    )
    response_length = _first_number(
        evidence,
        ("response_length", "baseline_response_length", "response_size"),
    )
    return (
        _validation_decision(result),
        _detection_methods(result),
        http_status,
        response_length,
        waf,
    )


class AgentToolExecutor:
    """Always applies policy before invoking an existing dispatcher handler."""

    def __init__(
        self,
        registry: AgentToolRegistry,
        policy_gate: AgentPolicyGate,
    ) -> None:
        if not isinstance(registry, AgentToolRegistry):
            raise TypeError("registry must be an AgentToolRegistry")
        if not isinstance(policy_gate, AgentPolicyGate):
            raise TypeError("policy_gate must be an AgentPolicyGate")
        if policy_gate.registry is not registry:
            raise ValueError("executor registry and policy registry must match")
        self.registry = registry
        self.policy_gate = policy_gate

    def execute(
        self,
        action: AgentAction,
        state: AgentState,
        *,
        session: Any = None,
    ) -> AgentExecution:
        policy = self.policy_gate.evaluate(action, state)
        if not policy.allowed:
            return AgentExecution(
                policy=policy,
                observation=AgentObservation(
                    action_id=action.action_id,
                    tool_id=action.tool_id,
                    finding_id=action.finding_id,
                    policy_decision=policy.code,
                    policy_allowed=False,
                    execution_status=AgentExecutionStatus.BLOCKED,
                    summary=policy.reason,
                    error_category=policy.code,
                    options_used=action.options,
                ),
            )

        original = state.finding_by_id(action.finding_id)
        if original is None:  # Defensive; policy already checks this.
            raise RuntimeError("policy allowed an unavailable finding")
        finding = _finding_with_options(original, action.options)
        try:
            validation = dispatch(finding, session=session)
            updated = enrich_finding_model(
                apply_validation_result(finding, validation)
            )
        except Exception:
            return AgentExecution(
                policy=policy,
                observation=AgentObservation(
                    action_id=action.action_id,
                    tool_id=action.tool_id,
                    finding_id=action.finding_id,
                    policy_decision=policy.code,
                    policy_allowed=True,
                    execution_status=AgentExecutionStatus.FAILED,
                    summary="The deterministic validator could not complete safely.",
                    error_category="validator_execution_error",
                    options_used=action.options,
                ),
            )

        capabilities = ()
        if validation.status == ValidationStatus.CONFIRMED:
            capabilities = tuple(
                capability
                for capability in updated.provides
                if capability not in state.capabilities
            )
        error_category = (
            "validator_reported_error" if validation.error else None
        )
        (
            validation_decision,
            detection_methods,
            http_status,
            response_length,
            waf_interference,
        ) = _observable_evidence(validation)
        return AgentExecution(
            policy=policy,
            updated_finding=updated,
            validation_result=validation,
            observation=AgentObservation(
                action_id=action.action_id,
                tool_id=action.tool_id,
                finding_id=action.finding_id,
                policy_decision=policy.code,
                policy_allowed=True,
                execution_status=AgentExecutionStatus.COMPLETED,
                validation_status=validation.status,
                capabilities_gained=capabilities,
                summary=(
                    "Deterministic validation completed with status "
                    f"{validation.status}."
                ),
                error_category=error_category,
                validation_decision=validation_decision,
                detection_methods=detection_methods,
                observed_http_status=http_status,
                observed_response_length=response_length,
                waf_or_filter_interference=waf_interference,
                options_used=action.options,
            ),
        )
