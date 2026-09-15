"""Small, traceable composition service for one bounded agent run."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from app.agent.executor import AgentExecution, AgentToolExecutor
from app.agent.llm_client import LLMClientConfig, OpenAICompatibleClient
from app.agent.llm_planner import LLMPlanner
from app.agent.models import AgentAction, AgentObservation, AgentState
from app.agent.orchestrator import AgentOrchestrator, Planner
from app.agent.policy import AgentPolicyGate, PolicyDecision
from app.agent.tools import AgentToolRegistry
from app.models.finding import Finding
from app.models.validation import ValidationResult


@dataclass(frozen=True)
class AgentRunStep:
    """One strict proposal and its deterministic policy/execution outcome."""

    step_number: int
    proposed_action: AgentAction
    policy_decision: PolicyDecision
    observation: AgentObservation
    validation_result: Optional[ValidationResult] = None
    updated_finding: Optional[Finding] = None

    def __post_init__(self) -> None:
        if isinstance(self.step_number, bool) or not isinstance(
            self.step_number,
            int,
        ):
            raise TypeError("step_number must be an integer")
        if self.step_number < 1:
            raise ValueError("step_number must be positive")
        if not isinstance(self.proposed_action, AgentAction):
            raise TypeError("proposed_action must be an AgentAction")
        if not isinstance(self.policy_decision, PolicyDecision):
            raise TypeError("policy_decision must be a PolicyDecision")
        if not isinstance(self.observation, AgentObservation):
            raise TypeError("observation must be an AgentObservation")
        if self.validation_result is not None and not isinstance(
            self.validation_result,
            ValidationResult,
        ):
            raise TypeError(
                "validation_result must be a ValidationResult or None"
            )
        if self.updated_finding is not None and not isinstance(
            self.updated_finding,
            Finding,
        ):
            raise TypeError("updated_finding must be a Finding or None")
        action = self.proposed_action
        policy = self.policy_decision
        observation = self.observation
        if (
            action.action_id != policy.action_id
            or action.tool_id != policy.tool_id
            or action.finding_id != policy.finding_id
            or action.action_id != observation.action_id
            or action.tool_id != observation.tool_id
            or action.finding_id != observation.finding_id
        ):
            raise ValueError("agent run step contains mismatched action context")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "proposed_action": self.proposed_action.to_dict(),
            "policy_decision": self.policy_decision.to_dict(),
            "observation": self.observation.to_dict(),
        }


@dataclass(frozen=True)
class AgentRunResult:
    """Sanitized demonstration view of one completed bounded run."""

    initial_state: AgentState
    final_state: AgentState
    steps: Tuple[AgentRunStep, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.initial_state, AgentState):
            raise TypeError("initial_state must be an AgentState")
        if not isinstance(self.final_state, AgentState):
            raise TypeError("final_state must be an AgentState")
        steps = tuple(self.steps)
        if not all(isinstance(step, AgentRunStep) for step in steps):
            raise TypeError("steps must contain AgentRunStep objects")
        object.__setattr__(self, "steps", steps)
        initial = self.initial_state
        final = self.final_state
        if (
            initial.scan_id != final.scan_id
            or initial.asset_id != final.asset_id
            or initial.target != final.target
            or initial.authorized != final.authorized
            or initial.scan_exists != final.scan_exists
        ):
            raise ValueError("agent run changed trusted scan context")

    @property
    def status(self) -> str:
        return self.final_state.status

    @property
    def stop_reason(self) -> Optional[str]:
        return self.final_state.terminal_reason

    @property
    def steps_used(self) -> int:
        return self.final_state.current_step - self.initial_state.current_step

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_state": self.initial_state.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "final_state": self.final_state.to_dict(),
            "status": self.status,
            "stop_reason": self.stop_reason,
            "steps_used": self.steps_used,
        }


class _RecordingPlanner:
    def __init__(self, planner: Planner) -> None:
        self.planner = planner
        self.actions: list[AgentAction] = []

    def propose_action(
        self,
        state: Dict[str, Any],
        available_tools: Sequence[Dict[str, Any]],
    ) -> Optional[AgentAction]:
        proposal = self.planner.propose_action(state, available_tools)
        if isinstance(proposal, AgentAction):
            self.actions.append(proposal)
        return proposal


class _RecordingExecutor(AgentToolExecutor):
    def __init__(
        self,
        registry: AgentToolRegistry,
        policy_gate: AgentPolicyGate,
    ) -> None:
        super().__init__(registry, policy_gate)
        self.executions: list[AgentExecution] = []

    def execute(
        self,
        action: AgentAction,
        state: AgentState,
        *,
        session: Any = None,
    ) -> AgentExecution:
        execution = super().execute(action, state, session=session)
        self.executions.append(execution)
        return execution


class AgentRunService:
    """Compose planner, policy, executor, and orchestrator without new powers."""

    def __init__(
        self,
        planner: Planner,
        *,
        registry: Optional[AgentToolRegistry] = None,
    ) -> None:
        if not isinstance(planner, Planner):
            raise TypeError("planner must implement propose_action")
        self.planner = planner
        self.registry = registry or AgentToolRegistry()
        if not isinstance(self.registry, AgentToolRegistry):
            raise TypeError("registry must be an AgentToolRegistry")

    @classmethod
    def from_environment(
        cls,
        environment: Optional[Mapping[str, str]] = None,
    ) -> "AgentRunService":
        """Build a configured planner without contacting its provider."""
        config = LLMClientConfig.from_environment(environment)
        client = OpenAICompatibleClient(config)
        return cls(LLMPlanner(client))

    def run(
        self,
        initial_state: AgentState,
        *,
        session: Any = None,
    ) -> AgentRunResult:
        """Run the existing bounded orchestrator and retain a safe step trace."""
        if not isinstance(initial_state, AgentState):
            raise TypeError("initial_state must be an AgentState")

        recording_planner = _RecordingPlanner(self.planner)
        policy_gate = AgentPolicyGate(self.registry)
        recording_executor = _RecordingExecutor(self.registry, policy_gate)
        orchestrator = AgentOrchestrator(
            registry=self.registry,
            executor=recording_executor,
            planner=recording_planner,
        )
        final_state = orchestrator.run(initial_state, session=session)

        if len(recording_planner.actions) != len(recording_executor.executions):
            raise RuntimeError("agent composition trace is inconsistent")
        steps = tuple(
            AgentRunStep(
                step_number=initial_state.current_step + index,
                proposed_action=action,
                policy_decision=execution.policy,
                observation=execution.observation,
                validation_result=execution.validation_result,
                updated_finding=execution.updated_finding,
            )
            for index, (action, execution) in enumerate(
                zip(
                    recording_planner.actions,
                    recording_executor.executions,
                    strict=True,
                ),
                start=1,
            )
        )
        return AgentRunResult(
            initial_state=initial_state,
            final_state=final_state,
            steps=steps,
        )
