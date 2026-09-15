"""Policy-enforced adapter from agent actions to registered tools and validators."""

from __future__ import annotations

from dataclasses import dataclass, replace
from numbers import Real
from typing import Any, Optional

import requests
from sqlalchemy.orm import Session as OrmSession

from app.agent.models import (
    AgentAction,
    AgentExecutionStatus,
    AgentObservation,
    AgentState,
)
from app.agent.policy import AgentPolicyGate, PolicyDecision
from app.agent.tools import ToolResult, execute_tool
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


def _map_options_for_tool(
    action: AgentAction,
    finding: Finding,
) -> Dict[str, Any]:
    """Translate AgentAction.options + finding context into tool-native options.

    AgentAction.options use validator-style keys (endpoint, http_method,
    parameter_name, parameter_location). Real tool executors expect
    tool-native keys (target, method, parameter, data, etc.).  This bridge
    resolves the difference so every tool receives the keys it needs.
    """
    opts: Dict[str, Any] = {}
    options_map = dict(action.options)

    # --- Resolve the full target URL ---
    endpoint = options_map.get("endpoint") or finding.endpoint or ""
    if endpoint and not endpoint.startswith(("http://", "https://")):
        target_base = action.target or finding.target or ""
        endpoint = target_base.rstrip("/") + "/" + endpoint.lstrip("/")
    opts["target"] = endpoint or (action.target or finding.target or "")

    # --- HTTP method ---
    method = options_map.get("http_method") or finding.http_method or "GET"
    opts["method"] = method.upper()

    # --- Parameter ---
    parameter = options_map.get("parameter_name") or finding.parameter_name or ""
    if parameter:
        opts["parameter"] = parameter

    parameter_location = options_map.get("parameter_location") or getattr(finding, "parameter_location", None) or ""
    if parameter_location:
        opts["parameter_location"] = parameter_location

    return opts


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


def _resolve_agent_http_session(session: Any) -> Any:
    """Return an HTTP-capable session for deterministic validators.

    Callers thread an opaque ``session`` object through the executor. The live
    API passes the SQLAlchemy DB session, but validators require an HTTP
    ``requests``-style session (``get``/``request``) to produce evidence. Pass
    the object through when usable and substitute a fresh HTTP session for a
    database session so validators actually run instead of degrading to
    manual review.
    """
    if session is None or isinstance(session, OrmSession):
        return requests.Session()
    return session


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
    """Apply policy, then dispatch to a registered tool or canonical validator."""

    def __init__(
        self,
        registry: Any = None,
        policy_gate: Optional[AgentPolicyGate] = None,
    ) -> None:
        if not isinstance(policy_gate, AgentPolicyGate):
            raise TypeError("policy_gate must be an AgentPolicyGate")
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
        tool_options = _map_options_for_tool(action, original)
        try:
            result = execute_tool(action.tool_id, tool_options)
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
                    summary="The selected tool could not be executed safely.",
                    error_category="tool_execution_error",
                    options_used=action.options,
                ),
            )

        if not result.extra.get("use_validator"):
            return self._from_tool_result(result, action, policy)

        try:
            validation = dispatch(
                finding, session=_resolve_agent_http_session(session)
            )
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

    def _from_tool_result(
        self,
        result: ToolResult,
        action: AgentAction,
        policy: PolicyDecision,
    ) -> AgentExecution:
        """Translate a non-validator tool result into a bounded observation."""
        success = bool(result.success)
        summary = _bounded_string(result.error if not success else result.output)
        if summary is None:
            summary = (
                "The tool reported success without output."
                if success
                else "The tool failed without a precise reason."
            )
        return AgentExecution(
            policy=policy,
            observation=AgentObservation(
                action_id=action.action_id,
                tool_id=action.tool_id,
                finding_id=action.finding_id,
                policy_decision=policy.code,
                policy_allowed=True,
                execution_status=(
                    AgentExecutionStatus.COMPLETED
                    if success
                    else AgentExecutionStatus.FAILED
                ),
                summary=summary,
                error_category=None if success else "tool_reported_error",
                options_used=action.options,
                shell_obtained=result.shell_obtained,
                shell_info=result.shell_info,
            ),
        )
