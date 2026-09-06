"""Optional bounded agent execution for the controlled test-harness flow."""

from __future__ import annotations

from dataclasses import replace
from typing import Callable, Optional, Sequence

from app.agent.models import AgentState, AgentStatus
from app.agent.run_service import AgentRunResult, AgentRunService
from app.scanning.http_discovery import ScopedReconHttpClient
from app.scanning.scope import AuthorizedTarget
from app.services.generic_local_web_validation import (
    GenericLocalWebRun,
    ScopedLoopbackHttpClient,
)


AGENT_MAXIMUM_STEPS = 2
AgentRunServiceFactory = Callable[[], AgentRunService]
AddressResolver = Callable[[str], Sequence[str]]


def build_controlled_demo_agent_state(run: GenericLocalWebRun) -> AgentState:
    """Build planner-safe state only from server-generated typed artifacts."""
    if not isinstance(run, GenericLocalWebRun):
        raise TypeError("run must be a GenericLocalWebRun")
    candidates = tuple(artifact.candidate for artifact in run.validations)
    return AgentState.from_findings(
        scan_id=run.scan_id,
        target=run.origin,
        asset_id=run.asset_id,
        authorized=True,
        findings=(run.reachability, *candidates),
        maximum_steps=AGENT_MAXIMUM_STEPS,
        attack_chain_ids=tuple(chain.chain_id for chain in run.chains),
    )


def _failed_run(state: AgentState, reason: str) -> AgentRunResult:
    return AgentRunResult(
        initial_state=state,
        final_state=replace(
            state,
            status=AgentStatus.FAILED,
            terminal_reason=reason,
        ),
        steps=(),
    )


def run_controlled_demo_agent(
    run: GenericLocalWebRun,
    *,
    authorized_target: Optional[AuthorizedTarget] = None,
    address_resolver: Optional[AddressResolver] = None,
    run_service_factory: AgentRunServiceFactory = (
        AgentRunService.from_environment
    ),
) -> AgentRunResult:
    """Run the existing agent safely without making assessment success depend on it."""
    state = build_controlled_demo_agent_state(run)
    try:
        service = run_service_factory()
        if not isinstance(service, AgentRunService):
            raise TypeError("agent service factory returned an invalid service")
    except Exception:
        return _failed_run(state, "agent_configuration_unavailable")

    try:
        if authorized_target is None:
            with ScopedLoopbackHttpClient(run.origin) as client:
                return service.run(state, session=client)
        with ScopedReconHttpClient(
            authorized_target,
            address_resolver=address_resolver,
        ) as client:
            return service.run(state, session=client)
    except Exception:
        return _failed_run(state, "agent_execution_unavailable")
