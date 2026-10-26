"""Strict contracts for the task-centric agent.

The planner receives and returns JSON only.  These dataclasses are the trusted
in-process representation of that JSON; no model output reaches an executor
without passing through them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from uuid import uuid4


MAX_GOAL_LENGTH = 4000
MAX_REASON_LENGTH = 512
MAX_EXPECTED_RESULT_LENGTH = 2000
MAX_ARGUMENT_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_COLLECTION_ITEMS = 100
MAX_RISK_LEVELS = frozenset({"low", "medium", "high"})
MAX_NETWORK_POLICIES = frozenset({"none", "lab", "allowlisted"})
MAX_TARGET_TYPES = frozenset({
    "local_file",
    "local_script",
    "docker_lab",
    "private_ip",
    "hostname",
    "test_application",
})


class TaskStatus:
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"

    TERMINAL = frozenset({
        COMPLETED,
        FAILED,
        INCONCLUSIVE,
        BLOCKED,
        TIMED_OUT,
        CANCELLED,
    })
    SUPPORTED = frozenset({
        CREATED,
        RUNNING,
        PAUSED,
        AWAITING_APPROVAL,
        COMPLETED,
        FAILED,
        INCONCLUSIVE,
        BLOCKED,
        TIMED_OUT,
        CANCELLED,
    })

    @classmethod
    def normalize(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("task status must be a non-empty string")
        normalized = value.strip().lower()
        if normalized not in cls.SUPPORTED:
            raise ValueError(f"unsupported task status {value!r}")
        return normalized


class VerificationStatus:
    COMPLETED = "completed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    VERIFIED_SUCCESS = "verified_success"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"

    SUPPORTED = frozenset({
        COMPLETED,
        FAILED,
        INCONCLUSIVE,
        VERIFIED_SUCCESS,
        BLOCKED,
        TIMED_OUT,
    })

    @classmethod
    def normalize(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("verification status must be a non-empty string")
        normalized = value.strip().lower()
        if normalized not in cls.SUPPORTED:
            raise ValueError(f"unsupported verification status {value!r}")
        return normalized


class Decision:
    RUN_REGISTERED_ACTION = "run_registered_action"
    GENERATE_CODE = "generate_code"
    INSPECT_ARTIFACT = "inspect_artifact"
    REPORT = "report"
    FINISH = "finish"

    SUPPORTED = frozenset({
        RUN_REGISTERED_ACTION,
        GENERATE_CODE,
        INSPECT_ARTIFACT,
        REPORT,
        FINISH,
    })


class RiskLevel:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SUPPORTED = MAX_RISK_LEVELS

    @classmethod
    def normalize(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("risk_level must be a non-empty string")
        normalized = value.strip().lower()
        if normalized not in cls.SUPPORTED:
            raise ValueError("risk_level must be low, medium, or high")
        return normalized


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _text(
    value: Any,
    name: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    normalized = value.strip()
    if not normalized and not allow_empty:
        raise ValueError(f"{name} must be a non-empty string")
    if len(normalized) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return normalized


def _string_tuple(
    value: Any,
    name: str,
    *,
    maximum_items: int = MAX_COLLECTION_ITEMS,
) -> Tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise TypeError(f"{name} must be a sequence of strings")
    try:
        values = tuple(value)
    except TypeError as exc:
        raise TypeError(f"{name} must be a sequence of strings") from exc
    if len(values) > maximum_items:
        raise ValueError(f"{name} contains too many items")
    normalized = tuple(dict.fromkeys(_text(item, name, maximum=2048) for item in values))
    return normalized


def _port_tuple(value: Any, name: str = "allowed_ports") -> Tuple[int, ...]:
    if isinstance(value, (str, bytes)):
        raise TypeError(f"{name} must be a sequence of ports")
    try:
        values = tuple(value)
    except TypeError as exc:
        raise TypeError(f"{name} must be a sequence of ports") from exc
    if len(values) > MAX_COLLECTION_ITEMS:
        raise ValueError(f"{name} contains too many items")
    ports = []
    for item in values:
        if isinstance(item, bool):
            raise TypeError(f"{name} must contain integers")
        try:
            port = int(item)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{name} must contain integers") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"{name} contains an invalid port")
        if port not in ports:
            ports.append(port)
    return tuple(sorted(ports))


def _bounded_mapping(
    value: Any,
    name: str,
    *,
    maximum_bytes: int = MAX_ARGUMENT_BYTES,
) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    if len(value) > MAX_COLLECTION_ITEMS:
        raise ValueError(f"{name} contains too many keys")
    result: Dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise TypeError(f"{name} keys must be non-empty strings")
        if len(key) > 128:
            raise ValueError(f"{name} contains an overlong key")
        result[key] = item
    try:
        size = len(json.dumps(result, default=str, separators=(",", ":")).encode())
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{name} is not JSON serializable") from exc
    if size > maximum_bytes:
        raise ValueError(f"{name} exceeds its size limit")
    return result


@dataclass(frozen=True)
class TaskContract:
    """A normalized, authorization-scoped task submitted by an operator."""

    task_id: str
    user_goal: str
    target: str
    target_type: str
    allowed_hosts: Tuple[str, ...] = field(default_factory=tuple)
    allowed_ports: Tuple[int, ...] = field(default_factory=tuple)
    authorized_lab_scope: bool = False
    input_files: Tuple[str, ...] = field(default_factory=tuple)
    expected_outputs: Tuple[str, ...] = field(default_factory=tuple)
    permitted_actions: Tuple[str, ...] = field(default_factory=tuple)
    maximum_steps: int = 12
    maximum_runtime: int = 900
    maximum_repair_attempts: int = 3
    network_policy: str = "none"
    approval_required: bool = False
    current_status: str = TaskStatus.CREATED
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "task_id", _text(self.task_id, "task_id", maximum=128)
        )
        object.__setattr__(
            self, "user_goal", _text(self.user_goal, "user_goal", maximum=MAX_GOAL_LENGTH)
        )
        object.__setattr__(
            self, "target", _text(self.target, "target", maximum=4096)
        )
        target_type = _text(self.target_type, "target_type", maximum=64).lower()
        if target_type not in MAX_TARGET_TYPES:
            raise ValueError("unsupported target_type")
        object.__setattr__(self, "target_type", target_type)
        object.__setattr__(
            self, "allowed_hosts", _string_tuple(self.allowed_hosts, "allowed_hosts")
        )
        object.__setattr__(
            self, "allowed_ports", _port_tuple(self.allowed_ports, "allowed_ports")
        )
        if type(self.authorized_lab_scope) is not bool:
            raise TypeError("authorized_lab_scope must be a boolean")
        object.__setattr__(
            self, "input_files", _string_tuple(self.input_files, "input_files")
        )
        object.__setattr__(
            self,
            "expected_outputs",
            _string_tuple(self.expected_outputs, "expected_outputs"),
        )
        object.__setattr__(
            self,
            "permitted_actions",
            _string_tuple(self.permitted_actions, "permitted_actions"),
        )
        for name in (
            "maximum_steps",
            "maximum_runtime",
            "maximum_repair_attempts",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
        if not 1 <= self.maximum_steps <= 50:
            raise ValueError("maximum_steps must be between 1 and 50")
        if not 1 <= self.maximum_runtime <= 7200:
            raise ValueError("maximum_runtime must be between 1 and 7200")
        if not 0 <= self.maximum_repair_attempts <= 10:
            raise ValueError("maximum_repair_attempts must be between 0 and 10")
        policy = _text(self.network_policy, "network_policy", maximum=32).lower()
        if policy not in MAX_NETWORK_POLICIES:
            raise ValueError("network_policy must be none, lab, or allowlisted")
        object.__setattr__(self, "network_policy", policy)
        if type(self.approval_required) is not bool:
            raise TypeError("approval_required must be a boolean")
        object.__setattr__(
            self, "current_status", TaskStatus.normalize(self.current_status)
        )
        if not isinstance(self.created_at, datetime):
            raise TypeError("created_at must be a datetime")
        if not isinstance(self.updated_at, datetime):
            raise TypeError("updated_at must be a datetime")

    @property
    def goal(self) -> str:
        return self.user_goal

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "user_goal": self.user_goal,
            "target": self.target,
            "target_type": self.target_type,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_ports": list(self.allowed_ports),
            "authorized_lab_scope": self.authorized_lab_scope,
            "input_files": list(self.input_files),
            "expected_outputs": list(self.expected_outputs),
            "permitted_actions": list(self.permitted_actions),
            "maximum_steps": self.maximum_steps,
            "maximum_runtime": self.maximum_runtime,
            "maximum_repair_attempts": self.maximum_repair_attempts,
            "network_policy": self.network_policy,
            "approval_required": self.approval_required,
            "current_status": self.current_status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskContract":
        if not isinstance(data, Mapping):
            raise TypeError("task contract must be an object")
        allowed = {
            "task_id",
            "user_goal",
            "target",
            "target_type",
            "allowed_hosts",
            "allowed_ports",
            "authorized_lab_scope",
            "input_files",
            "expected_outputs",
            "permitted_actions",
            "maximum_steps",
            "maximum_runtime",
            "maximum_repair_attempts",
            "network_policy",
            "approval_required",
            "current_status",
            "created_at",
            "updated_at",
        }
        extras = set(data) - allowed
        if extras:
            raise ValueError("unsupported task fields: " + ", ".join(sorted(extras)))
        values = dict(data)
        values.setdefault("task_id", f"task-{uuid4()}")
        for key in ("created_at", "updated_at"):
            if isinstance(values.get(key), str):
                values[key] = datetime.fromisoformat(values[key].replace("Z", "+00:00"))
        return cls(**values)


@dataclass(frozen=True)
class PlannerDecision:
    """The only shape a planner may propose."""

    decision: str
    action_id: str
    reason: str
    arguments: Dict[str, Any]
    target: str
    expected_result: str
    risk_level: str
    requires_approval: bool = False

    def __post_init__(self) -> None:
        decision = _text(self.decision, "decision", maximum=64).lower()
        if decision not in Decision.SUPPORTED:
            raise ValueError("unsupported planner decision")
        object.__setattr__(self, "decision", decision)
        object.__setattr__(
            self, "action_id", _text(self.action_id, "action_id", maximum=128)
        )
        object.__setattr__(
            self, "reason", _text(self.reason, "reason", maximum=MAX_REASON_LENGTH)
        )
        object.__setattr__(
            self, "arguments", _bounded_mapping(self.arguments, "arguments")
        )
        object.__setattr__(
            self, "target", _text(self.target, "target", maximum=4096)
        )
        object.__setattr__(
            self,
            "expected_result",
            _text(
                self.expected_result,
                "expected_result",
                maximum=MAX_EXPECTED_RESULT_LENGTH,
            ),
        )
        object.__setattr__(self, "risk_level", RiskLevel.normalize(self.risk_level))
        if type(self.requires_approval) is not bool:
            raise TypeError("requires_approval must be a boolean")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PlannerDecision":
        if not isinstance(data, Mapping):
            raise TypeError("planner decision must be an object")
        allowed = {
            "decision",
            "action_id",
            "reason",
            "arguments",
            "target",
            "expected_result",
            "risk_level",
            "requires_approval",
        }
        extras = set(data) - allowed
        if extras:
            raise ValueError("unsupported planner fields: " + ", ".join(sorted(extras)))
        missing = allowed - set(data)
        if missing:
            raise ValueError("missing planner fields: " + ", ".join(sorted(missing)))
        return cls(**data)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "action_id": self.action_id,
            "reason": self.reason,
            "arguments": self.arguments,
            "target": self.target,
            "expected_result": self.expected_result,
            "risk_level": self.risk_level,
            "requires_approval": self.requires_approval,
        }


@dataclass(frozen=True)
class VerificationCheck:
    name: str
    passed: bool
    detail: str = ""
    observed: Any = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "name", maximum=128))
        if type(self.passed) is not bool:
            raise TypeError("passed must be a boolean")
        object.__setattr__(
            self, "detail", _text(self.detail, "detail", maximum=1024, allow_empty=True)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class VerificationResult:
    status: str
    checks: Tuple[VerificationCheck, ...] = field(default_factory=tuple)
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", VerificationStatus.normalize(self.status))
        checks = tuple(self.checks)
        if not all(isinstance(check, VerificationCheck) for check in checks):
            raise TypeError("checks must contain VerificationCheck objects")
        object.__setattr__(self, "checks", checks)
        object.__setattr__(
            self,
            "reason",
            _text(self.reason, "reason", maximum=2048, allow_empty=True),
        )

    @property
    def verified(self) -> bool:
        return self.status == VerificationStatus.VERIFIED_SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "checks": [check.to_dict() for check in self.checks],
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ExecutionObservation:
    """Structured result returned to the planner and persisted as evidence."""

    status: str
    action_id: str
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    verification: VerificationResult = field(
        default_factory=lambda: VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason="not verified",
        )
    )
    artifacts: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    evidence: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    session_updates: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    error: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "status", VerificationStatus.normalize(self.status)
        )
        object.__setattr__(
            self, "action_id", _text(self.action_id, "action_id", maximum=128)
        )
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise TypeError("exit_code must be an integer or None")
        for name in ("stdout", "stderr"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            encoded = value.encode("utf-8", errors="replace")
            if len(encoded) > MAX_OUTPUT_BYTES:
                value = encoded[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            object.__setattr__(self, name, value)
        object.__setattr__(
            self, "parsed_data", _bounded_mapping(self.parsed_data, "parsed_data")
        )
        if not isinstance(self.verification, VerificationResult):
            raise TypeError("verification must be a VerificationResult")
        artifacts = tuple(self.artifacts)
        evidence = tuple(self.evidence)
        if len(artifacts) > MAX_COLLECTION_ITEMS or len(evidence) > MAX_COLLECTION_ITEMS:
            raise ValueError("observation collections are too large")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(
            self,
            "session_updates",
            _bounded_mapping(self.session_updates, "session_updates"),
        )
        if isinstance(self.duration_seconds, bool) or not isinstance(
            self.duration_seconds, (int, float)
        ):
            raise TypeError("duration_seconds must be numeric")
        object.__setattr__(self, "duration_seconds", max(0.0, float(self.duration_seconds)))
        if self.error is not None:
            object.__setattr__(
                self,
                "error",
                _text(self.error, "error", maximum=2048),
            )

    @property
    def verified(self) -> bool:
        return self.verification.verified

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "action_id": self.action_id,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "parsed_data": self.parsed_data,
            "verification": self.verification.to_dict(),
            "artifacts": list(self.artifacts),
            "evidence": list(self.evidence),
            "session_updates": self.session_updates,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


def strict_json_loads(content: str) -> Dict[str, Any]:
    """Parse one JSON object, rejecting duplicate keys and non-finite values."""

    if not isinstance(content, str):
        raise TypeError("content must be a string")

    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"unsupported JSON constant {value}")

    import json as _json

    text = content.strip()
    if text.startswith("```") and text.endswith("```"):
        lines = text.splitlines()
        if len(lines) >= 2 and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1]).strip()
    return _json.loads(
        text,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def is_sha256(value: str) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


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
    "strict_json_loads",
]
