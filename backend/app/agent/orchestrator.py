"""Bounded observe-plan-policy-execute loop with no model provider."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, Optional, Protocol, Sequence, runtime_checkable

from app.agent.executor import AgentExecution, AgentToolExecutor
from app.agent.models import (
    AgentAction,
    AgentExecutionStatus,
    AgentObservation,
    AgentState,
    AgentStatus,
)
from app.agent.tools import AgentToolRegistry, get_available_tool_catalog


@runtime_checkable
class Planner(Protocol):
    """Provider-independent planner receiving only sanitized state/tool views."""

    def propose_action(
        self,
        state: Dict[str, Any],
        available_tools: Sequence[Dict[str, Any]],
    ) -> Optional[AgentAction]:
        ...


def _apply_execution(
    state: AgentState,
    execution: AgentExecution,
) -> AgentState:
    findings = state.findings
    updated = execution.updated_finding
    if updated is not None:
        findings = tuple(
            updated if finding.finding_id == updated.finding_id else finding
            for finding in findings
        )
    capabilities = tuple(dict.fromkeys((
        *state.capabilities,
        *execution.observation.capabilities_gained,
    )))
    techniques = list(state.mitre_techniques)
    if updated is not None and updated.mitre_technique_id:
        techniques.append(updated.mitre_technique_id)
    executed_ids = state.executed_action_ids
    if execution.observation.policy_allowed:
        executed_ids = tuple(dict.fromkeys((
            *executed_ids,
            execution.observation.action_id,
        )))
    return replace(
        state,
        findings=findings,
        capabilities=capabilities,
        mitre_techniques=tuple(dict.fromkeys(techniques)),
        observations=(*state.observations, execution.observation),
        executed_action_ids=executed_ids,
        current_step=state.current_step + 1,
    )


class AgentOrchestrator:
    """Run exactly one bounded security agent using an injected planner."""

    def __init__(
        self,
        *,
        registry: AgentToolRegistry,
        executor: AgentToolExecutor,
        planner: Planner,
    ) -> None:
        if not isinstance(registry, AgentToolRegistry):
            raise TypeError("registry must be an AgentToolRegistry")
        if not isinstance(executor, AgentToolExecutor):
            raise TypeError("executor must be an AgentToolExecutor")
        if executor.registry is not registry:
            raise ValueError("orchestrator and executor registries must match")
        if not isinstance(planner, Planner):
            raise TypeError("planner must implement propose_action")
        self.registry = registry
        self.executor = executor
        self.planner = planner

    def run(
        self,
        initial_state: AgentState,
        *,
        session: Any = None,
    ) -> AgentState:
        if not isinstance(initial_state, AgentState):
            raise TypeError("initial_state must be an AgentState")
        if initial_state.status != AgentStatus.READY:
            return replace(
                initial_state,
                status=AgentStatus.BLOCKED,
                terminal_reason="agent_state_not_ready",
            )

        state = replace(initial_state, status=AgentStatus.RUNNING)
        while state.current_step < state.maximum_steps:
            try:
                proposal = self.planner.propose_action(
                    state.to_dict(),
                    get_available_tool_catalog(),
                )
            except Exception:
                return replace(
                    state,
                    status=AgentStatus.FAILED,
                    terminal_reason="planner_error",
                )
            if proposal is None:
                return replace(
                    state,
                    status=AgentStatus.COMPLETED,
                    terminal_reason="planner_completed",
                )
            if not isinstance(proposal, AgentAction):
                observation = AgentObservation(
                    action_id=f"invalid-planner-output-{state.current_step + 1}",
                    tool_id="planner",
                    finding_id=None,
                    policy_decision="invalid_planner_output",
                    policy_allowed=False,
                    execution_status=AgentExecutionStatus.FAILED,
                    summary="Planner output was not a valid AgentAction.",
                    error_category="invalid_planner_output",
                )
                return replace(
                    state,
                    observations=(*state.observations, observation),
                    current_step=state.current_step + 1,
                    status=AgentStatus.FAILED,
                    terminal_reason="invalid_planner_output",
                )

            execution = self.executor.execute(
                proposal,
                state,
                session=session,
            )
            state = _apply_execution(state, execution)
            if execution.observation.execution_status == AgentExecutionStatus.BLOCKED:
                return replace(
                    state,
                    status=AgentStatus.BLOCKED,
                    terminal_reason=execution.policy.code,
                )
            if execution.observation.execution_status == AgentExecutionStatus.FAILED:
                return replace(
                    state,
                    status=AgentStatus.FAILED,
                    terminal_reason=execution.observation.error_category,
                )

        return replace(
            state,
            status=AgentStatus.BLOCKED,
            terminal_reason="step_limit_reached",
        )
