"""Bounded, task-centric agent layer for Obsidian Recon.

The existing finding-centric agent remains in :mod:`app.agent`.  This package
adds a task contract, a registered-action catalog, generated-code isolation,
verification, evidence persistence, reporting, and runtime Claude-Red
methodology retrieval without replacing the existing LLM integration.
"""

from app.task_agent.contracts import (  # noqa: F401
    Decision,
    ExecutionObservation,
    PlannerDecision,
    RiskLevel,
    TaskContract,
    TaskStatus,
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
)

__all__ = [
    "Decision",
    "ExecutionObservation",
    "PlannerDecision",
    "RiskLevel",
    "TaskContract",
    "TaskStatus",
    "VerificationCheck",
    "VerificationResult",
    "VerificationStatus",
]
