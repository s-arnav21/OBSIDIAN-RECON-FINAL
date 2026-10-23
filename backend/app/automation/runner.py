"""Technique runner — bridges automation scripts to the agent execution loop.

The agent executor calls :func:`run_technique_execution` for any action whose
``tool_id`` is ``technique:<Txxxx>``. The runner assembles an
``AutomationContext`` from the trusted agent state, runs the technique script,
and translates its ``TechniqueResult`` into the ``AgentExecution`` /
``AgentObservation`` contract the orchestrator already understands.

A technique that reports ``blocked``/``error`` does **not** terminate the run —
it is surfaced as a completed observation with an ``error_category`` so a chain
can degrade gracefully (e.g. skip a technique whose binary is missing) instead
of aborting.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, Optional

from app.agent.executor import AgentExecution
from app.agent.models import (
    AgentAction,
    AgentExecutionStatus,
    AgentObservation,
    AgentState,
)
from app.agent.policy import PolicyDecision
from app.automation import adapters, get_technique
from app.automation.base import AutomationContext, TechniqueResult, TechniqueStatus
from app.automation.policy import TECHNIQUE_TOOL_PREFIX
from app.models.finding import Finding, ValidationStatus


def _technique_id_for(tool_id: str) -> str:
    if tool_id.startswith(TECHNIQUE_TOOL_PREFIX):
        return tool_id[len(TECHNIQUE_TOOL_PREFIX):]
    return tool_id


def _validation_status_for(status: str) -> Optional[str]:
    if status == TechniqueStatus.CONFIRMED:
        return ValidationStatus.CONFIRMED
    if status == TechniqueStatus.REJECTED:
        return ValidationStatus.REJECTED
    return None


def build_context(
    action: AgentAction,
    state: AgentState,
    *,
    session: Any = None,
    target_session: Any = None,
    credentials: Optional[Dict[str, str]] = None,
) -> AutomationContext:
    """Assemble a technique execution context from trusted agent state.

    ``session`` is the caller's DB/HTTP session (unchanged). ``target_session``
    is an optional ready authenticated session on the authorized target, and
    ``credentials`` is bounded credential material recovered earlier so a
    technique can validate it (open a real session) instead of trusting the
    recovery step alone.
    """
    from app.core.config import settings

    finding = state.finding_by_id(action.finding_id)
    return AutomationContext(
        target=state.target,
        authorized=state.authorized,
        finding=finding,
        options=dict(action.options),
        capabilities=tuple(state.capabilities),
        http_session=adapters.resolve_http_session(session),
        db_session=session,
        artifact_dir=settings.AUTOMATION_ARTIFACT_DIR or None,
        timeout_seconds=settings.AUTOMATION_TIMEOUT,
        allow_remote_fetch=settings.AUTOMATION_ALLOW_REMOTE_FETCH,
        session=target_session,
        credentials=dict(credentials or {}),
    )


def run_technique(technique_id: str, ctx: AutomationContext) -> TechniqueResult:
    """Run one technique script by id. Never raises."""
    try:
        script = get_technique(technique_id)
    except KeyError:
        return TechniqueResult(
            technique_id=technique_id,
            status=TechniqueStatus.BLOCKED,
            summary=f"unknown technique {technique_id!r}",
            error="unknown_technique",
        )
    try:
        return script.execute(ctx)
    except Exception as exc:  # noqa: BLE001 — a technique never aborts a chain
        return TechniqueResult(
            technique_id=technique_id,
            status=TechniqueStatus.ERROR,
            summary="technique raised an unexpected error",
            error=f"{type(exc).__name__}: {exc}"[:512],
        )


def _updated_finding(finding: Optional[Finding], result: TechniqueResult) -> Optional[Finding]:
    if finding is None or not result.confirmed:
        return finding
    provides = list(dict.fromkeys((*finding.provides, *result.provides)))
    return replace(
        finding,
        provides=provides,
        validation_status=ValidationStatus.CONFIRMED,
    )


def run_technique_execution(
    action: AgentAction,
    state: AgentState,
    policy: PolicyDecision,
    *,
    session: Any = None,
) -> AgentExecution:
    """Execute a technique action and return an AgentExecution."""
    technique_id = _technique_id_for(action.tool_id)
    ctx = build_context(action, state, session=session)
    result = run_technique(technique_id, ctx)

    finding = state.finding_by_id(action.finding_id)
    # block/error/skip are non-terminal so the chain continues.
    execution_status = AgentExecutionStatus.COMPLETED
    error_category = result.error if result.status in {
        TechniqueStatus.ERROR,
        TechniqueStatus.BLOCKED,
        TechniqueStatus.SKIPPED,
    } else None

    return AgentExecution(
        policy=policy,
        updated_finding=_updated_finding(finding, result),
        observation=AgentObservation(
            action_id=action.action_id,
            tool_id=action.tool_id,
            finding_id=action.finding_id,
            policy_decision=policy.code,
            policy_allowed=True,
            execution_status=execution_status,
            summary=result.summary,
            validation_status=_validation_status_for(result.status),
            capabilities_gained=result.capabilities_gained,
            error_category=error_category,
            options_used=action.options,
        ),
    )


__all__ = [
    "build_context",
    "run_technique",
    "run_technique_execution",
    "TechniqueResult",
]
