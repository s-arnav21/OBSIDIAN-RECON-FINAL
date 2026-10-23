"""Deterministic kill-chain planning over the technique registry.

The LLM planner chooses techniques opportunistically; this module provides a
provider-free fallback that selects the next applicable technique from the
registry in a fixed priority order. It is used by the ``python -m app.automation
chain`` CLI and available to the agent as a deterministic policy-compatible
planner.

It mirrors the gate's strict prerequisite model: a technique is only proposed
when its ``requires_any``/``requires_all`` are satisfied by capabilities that
were genuinely obtained (confirmed findings' ``provides`` plus capabilities
granted by earlier successful observations).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.agent.models import AgentAction, AgentState
from app.agent.tools import normalize_vulnerability_type
from app.automation import all_techniques, get_technique
from app.automation.policy import true_capabilities

#: Order in which the deterministic chain attempts techniques.
TECHNIQUE_PRIORITY = (
    "T1595",
    "T1190",
    "T1078",
    "T1059.004",
    "T1082",
    "T1548",
    "T1068",
    "T1213",
)

_OPTION_KEYS = ("endpoint", "http_method", "parameter_name", "parameter_location")


def _normalize_types(values) -> set:
    return {normalize_vulnerability_type(str(value)) for value in values or ()}


def _true_caps_from_view(state: Dict[str, Any]) -> set:
    from app.attack_chain.engine import BASE_CAPABILITIES

    capabilities = set(BASE_CAPABILITIES)
    for finding in state.get("findings", ()) or ():
        if not isinstance(finding, dict):
            continue
        if finding.get("validation_status") == "confirmed":
            capabilities.update(finding.get("provides", ()) or ())
    for observation in state.get("observations", ()) or ():
        if isinstance(observation, dict):
            capabilities.update(observation.get("capabilities_gained", ()) or ())
    return capabilities


def _candidate_findings(state: Dict[str, Any], vuln_types: set) -> List[Dict[str, Any]]:
    findings = [f for f in state.get("findings", ()) or () if isinstance(f, dict)]
    if not vuln_types:
        return findings
    return [
        finding
        for finding in findings
        if normalize_vulnerability_type(str(finding.get("vulnerability_type", "")))
        in vuln_types
    ]


def _options_for(finding: Dict[str, Any]) -> tuple:
    options = []
    for key in _OPTION_KEYS:
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            options.append((key, value.strip()))
    return tuple(options)


class ChainPlanner:
    """Provider-free planner that advances a technique kill chain."""

    def __init__(self, priority=TECHNIQUE_PRIORITY) -> None:
        self.priority = tuple(priority)
        # Ensure the registry is populated once.
        all_techniques()

    def propose_action(
        self,
        state: Dict[str, Any],
        available_tools,
    ) -> Optional[AgentAction]:
        if not isinstance(state, dict):
            return None
        capabilities = _true_caps_from_view(state)
        executed = {
            (observation.get("tool_id"), observation.get("finding_id"))
            for observation in state.get("observations", ()) or ()
            if isinstance(observation, dict) and observation.get("policy_allowed")
        }

        for technique_id in self.priority:
            try:
                technique = get_technique(technique_id)
            except KeyError:
                continue
            if technique.requires_all and not all(
                requirement in capabilities
                for requirement in technique.requires_all
            ):
                continue
            if technique.requires_any and not any(
                requirement in capabilities
                for requirement in technique.requires_any
            ):
                continue
            # Do not re-run a technique whose outputs are already held.
            if technique.provides and all(
                capability in capabilities for capability in technique.provides
            ):
                continue

            for finding in _candidate_findings(
                state, _normalize_types(technique.vuln_types)
            ):
                tool_id = f"technique:{technique_id}"
                finding_id = finding.get("finding_id")
                if not finding_id or (tool_id, finding_id) in executed:
                    continue
                step = state.get("current_step", 0)
                return AgentAction.from_dict({
                    "action_id": f"chain-{technique_id}-{finding_id}-{step}",
                    "tool_id": tool_id,
                    "scan_id": state["scan_id"],
                    "asset_id": state["asset_id"],
                    "finding_id": finding_id,
                    "target": state["target"],
                    "reason": (
                        f"Deterministic chain step {step + 1}: "
                        f"{technique_id} on {finding_id}."
                    ),
                    "expected_capabilities": list(technique.requires_any),
                    "options": list(_options_for(finding)),
                })
        return None


def run_chain(initial_state: AgentState, *, session: Any = None):
    """Run a deterministic technique chain to completion or the step limit."""
    from app.agent.run_service import AgentRunService

    return AgentRunService(ChainPlanner()).run(initial_state, session=session)


__all__ = ["ChainPlanner", "run_chain", "TECHNIQUE_PRIORITY"]
