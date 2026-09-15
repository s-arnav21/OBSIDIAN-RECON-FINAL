"""Compact typed contracts for one bounded Obsidian security agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from app.attack_chain.engine import BASE_CAPABILITIES
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.core.config import settings
from app.models.finding import Finding, ParameterLocation, ValidationStatus
from app.scanning.scope import ReconScopeError, normalize_origin


ABSOLUTE_MAX_AGENT_STEPS = settings.AGENT_MAX_STEPS
MAX_AGENT_FINDINGS = 100
MAX_STATE_COLLECTION_ITEMS = 100
MAX_REASON_LENGTH = 256
MAX_SUMMARY_LENGTH = 512
MAX_PLANNER_FIELD_LENGTH = 512

# Bounded targeting options an operator-style planner may attach to an action.
# The LLM selects where/how to probe (same-origin path, method, parameter,
# placement); deterministic validators still craft every payload.
MAX_ACTION_OPTIONS = 4
MAX_ACTION_OPTION_VALUE_LENGTH = 512
ACTION_OPTION_KEYS = frozenset({
    "endpoint",
    "http_method",
    "parameter_name",
    "parameter_location",
})
_ACTION_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})
_ACTION_PARAMETER_LOCATIONS = frozenset(
    location
    for location in ParameterLocation.SUPPORTED
    if location != ParameterLocation.PATH
)


class AgentStatus:
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"

    SUPPORTED = frozenset({READY, RUNNING, COMPLETED, BLOCKED, FAILED})


class AgentExecutionStatus:
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"

    SUPPORTED = frozenset({COMPLETED, BLOCKED, FAILED})


def _required_string(value: Any, name: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise ValueError(f"{name} exceeds its maximum length")
    return normalized


def _optional_string(
    value: Any,
    name: str,
    *,
    maximum: int = 512,
) -> Optional[str]:
    if value is None:
        return None
    return _required_string(value, name, maximum=maximum)


def _string_tuple(values: Iterable[str], name: str) -> Tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be a sequence of strings")
    normalized = tuple(values)
    if len(normalized) > MAX_STATE_COLLECTION_ITEMS:
        raise ValueError(f"{name} contains too many items")
    if not all(isinstance(value, str) and value.strip() for value in normalized):
        raise TypeError(f"{name} must contain non-empty strings")
    if any(len(value.strip()) > MAX_PLANNER_FIELD_LENGTH for value in normalized):
        raise ValueError(f"{name} contains an oversized value")
    return tuple(dict.fromkeys(value.strip() for value in normalized))


def _bounded_string_map(
    values: Any,
    name: str,
    *,
    key_maximum: int = 128,
    value_maximum: int = 256,
    max_items: int = 10,
) -> Dict[str, str]:
    """Coerce an arbitrary mapping into bounded non-control-char strings."""
    if values is None:
        return {}
    if not isinstance(values, dict):
        raise TypeError(f"{name} must be a dict if provided")
    if len(values) > max_items:
        raise ValueError(f"{name} contains too many items")
    result: Dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not key.strip():
            continue
        if not isinstance(value, str):
            continue
        safe_key = key.strip()[:key_maximum]
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in safe_key):
            continue
        safe_value = value.strip()[:value_maximum]
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in safe_value):
            continue
        result[safe_key] = safe_value
    return result


def _same_origin(left: str, right: str) -> bool:
    try:
        return normalize_origin(left).origin == normalize_origin(right).origin
    except ReconScopeError:
        return False


def _normalize_options(
    options: Any,
) -> Tuple[Tuple[str, str], ...]:
    """Canonicalize bounded targeting options into sorted (key, value) pairs.

    Option keys are allowlisted, values are non-empty printable strings with
    strict enums for ``http_method`` and ``parameter_location``. The options
    tuple is sorted so equal option sets compare equal regardless of order.
    """
    if isinstance(options, (str, bytes)):
        raise TypeError("agent action options must be a mapping or pair list")
    if isinstance(options, Mapping):
        items = list(options.items())
    else:
        items = list(options)
    if len(items) > MAX_ACTION_OPTIONS:
        raise ValueError("agent action options exceeds its size limit")
    seen = set()
    normalized = []
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError(
                "agent action options must be (key, value) pairs"
            )
        key, value = item
        if not isinstance(key, str) or key not in ACTION_OPTION_KEYS:
            raise ValueError(f"unsupported agent action option {key!r}")
        if key in seen:
            raise ValueError(f"duplicate agent action option {key!r}")
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"agent action option {key!r} must be a non-empty string"
            )
        value = value.strip()
        if len(value) > MAX_ACTION_OPTION_VALUE_LENGTH:
            raise ValueError(
                f"agent action option {key!r} exceeds its maximum length"
            )
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError(
                f"agent action option {key!r} contains control characters"
            )
        if key == "http_method":
            value = value.upper()
            if value not in _ACTION_HTTP_METHODS:
                raise ValueError(f"unsupported agent action http_method {value!r}")
        elif key == "parameter_location":
            location = ParameterLocation.normalize(value)
            if location not in _ACTION_PARAMETER_LOCATIONS:
                raise ValueError(
                    f"unsupported agent action parameter_location {value!r}"
                )
            value = location
        seen.add(key)
        normalized.append((key, value))
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class AgentAction:
    """A planner may select one registered tool for one scoped finding."""

    action_id: str
    tool_id: str
    scan_id: str
    asset_id: str
    finding_id: str
    target: str
    reason: str
    expected_capabilities: Tuple[str, ...] = field(default_factory=tuple)
    options: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in (
            "action_id",
            "tool_id",
            "scan_id",
            "asset_id",
            "finding_id",
            "target",
        ):
            object.__setattr__(
                self,
                name,
                _required_string(getattr(self, name), name),
            )
        object.__setattr__(
            self,
            "reason",
            _required_string(
                self.reason,
                "reason",
                maximum=MAX_REASON_LENGTH,
            ),
        )
        object.__setattr__(
            self,
            "expected_capabilities",
            _string_tuple(
                self.expected_capabilities,
                "expected_capabilities",
            ),
        )
        object.__setattr__(self, "options", _normalize_options(self.options))

    @property
    def options_key(self) -> Tuple[Tuple[str, str], ...]:
        """Canonical duplicate-key: equal options deduplicate, variants retry."""
        return self.options

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "tool_id": self.tool_id,
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "finding_id": self.finding_id,
            "target": self.target,
            "reason": self.reason,
            "expected_capabilities": list(self.expected_capabilities),
            "options": dict(self.options),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentAction":
        if not isinstance(data, dict):
            raise TypeError("agent action data must be a dictionary")
        allowed = {
            "action_id",
            "tool_id",
            "scan_id",
            "asset_id",
            "finding_id",
            "target",
            "reason",
            "expected_capabilities",
            "options",
        }
        extras = sorted(set(data) - allowed)
        if extras:
            raise ValueError(
                "unsupported AgentAction fields: " + ", ".join(extras)
            )
        required = allowed - {"expected_capabilities", "options"}
        missing = sorted(required - set(data))
        if missing:
            raise ValueError(
                "missing AgentAction fields: " + ", ".join(missing)
            )
        return cls(**data)


@dataclass(frozen=True)
class AgentObservation:
    """Bounded, sanitized feedback returned to a future planner."""

    action_id: str
    tool_id: str
    finding_id: Optional[str]
    policy_decision: str
    policy_allowed: bool
    execution_status: str
    summary: str
    validation_status: Optional[str] = None
    capabilities_gained: Tuple[str, ...] = field(default_factory=tuple)
    error_category: Optional[str] = None
    validation_decision: Optional[str] = None
    detection_methods: Tuple[str, ...] = field(default_factory=tuple)
    observed_http_status: Optional[int] = None
    observed_response_length: Optional[int] = None
    waf_or_filter_interference: bool = False
    options_used: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)
    shell_obtained: bool = False
    shell_info: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("action_id", "tool_id", "policy_decision"):
            object.__setattr__(
                self,
                name,
                _required_string(getattr(self, name), name),
            )
        object.__setattr__(
            self,
            "finding_id",
            _optional_string(self.finding_id, "finding_id"),
        )
        if type(self.policy_allowed) is not bool:
            raise TypeError("policy_allowed must be a boolean")
        if self.execution_status not in AgentExecutionStatus.SUPPORTED:
            raise ValueError("unsupported agent execution status")
        object.__setattr__(
            self,
            "summary",
            _required_string(
                self.summary,
                "summary",
                maximum=MAX_SUMMARY_LENGTH,
            ),
        )
        if self.validation_status is not None:
            object.__setattr__(
                self,
                "validation_status",
                ValidationStatus.normalize(self.validation_status),
            )
        object.__setattr__(
            self,
            "capabilities_gained",
            _string_tuple(self.capabilities_gained, "capabilities_gained"),
        )
        object.__setattr__(
            self,
            "error_category",
            _optional_string(self.error_category, "error_category"),
        )
        object.__setattr__(
            self,
            "validation_decision",
            _optional_string(
                self.validation_decision,
                "validation_decision",
                maximum=MAX_SUMMARY_LENGTH,
            ),
        )
        object.__setattr__(
            self,
            "detection_methods",
            _string_tuple(self.detection_methods, "detection_methods"),
        )
        for name, maximum in (
            ("observed_http_status", 599),
            ("observed_response_length", 10_000_000),
        ):
            value = getattr(self, name)
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, int):
                    raise TypeError(f"{name} must be an integer or None")
                if not 0 <= value <= maximum:
                    raise ValueError(f"{name} is outside the supported range")
        if type(self.waf_or_filter_interference) is not bool:
            raise TypeError("waf_or_filter_interference must be a boolean")
        object.__setattr__(
            self,
            "options_used",
            _normalize_options(self.options_used),
        )
        if type(self.shell_obtained) is not bool:
            raise TypeError("shell_obtained must be a boolean")
        object.__setattr__(
            self,
            "shell_info",
            _bounded_string_map(self.shell_info, "shell_info"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "tool_id": self.tool_id,
            "finding_id": self.finding_id,
            "policy_decision": self.policy_decision,
            "policy_allowed": self.policy_allowed,
            "execution_status": self.execution_status,
            "validation_status": self.validation_status,
            "capabilities_gained": list(self.capabilities_gained),
            "summary": self.summary,
            "error_category": self.error_category,
            "validation_decision": self.validation_decision,
            "detection_methods": list(self.detection_methods),
            "observed_http_status": self.observed_http_status,
            "observed_response_length": self.observed_response_length,
            "waf_or_filter_interference": self.waf_or_filter_interference,
            "options_used": list(self.options_used),
            "shell_obtained": self.shell_obtained,
            "shell_info": self.shell_info,
        }


def _finding_view(finding: Finding) -> Dict[str, Any]:
    """Expose reasoning context without raw evidence or request state."""
    def bounded(value: Optional[str], maximum: int = 256) -> Optional[str]:
        if value is None or len(value) <= maximum:
            return value
        return f"{value[:maximum - 1]}…"

    def bounded_capabilities(values: Sequence[str]) -> list[str]:
        return [bounded(value, 128) or "" for value in values[:20]]

    return {
        "finding_id": finding.finding_id,
        "scan_id": finding.scan_id,
        "asset_id": finding.asset_id,
        "target": finding.target,
        "vulnerability_type": bounded(finding.vulnerability_type, 128),
        "severity": bounded(finding.severity, 64),
        "validator_id": bounded(finding.validator_id, 128),
        "endpoint": bounded(finding.endpoint, 512),
        "http_method": bounded(finding.http_method, 16),
        "parameter_name": bounded(finding.parameter_name, 128),
        "parameter_location": bounded(finding.parameter_location, 32),
        "validation_status": finding.validation_status,
        "validation_confidence": finding.validation_confidence,
        "mitre_technique_id": finding.mitre_technique_id,
        "mitre_technique_name": finding.mitre_technique_name,
        "mitre_tactic": finding.mitre_tactic,
        "requires_all": bounded_capabilities(finding.effective_requires_all),
        "requires_any": bounded_capabilities(finding.effective_requires_any),
        "provides": bounded_capabilities(finding.provides),
    }


@dataclass(frozen=True)
class AgentState:
    """Trusted in-memory runtime state; serialization is planner-safe."""

    scan_id: str
    target: str
    asset_id: str
    authorized: bool
    findings: Tuple[Finding, ...] = field(default_factory=tuple)
    scan_exists: bool = True
    capabilities: Tuple[str, ...] = field(default_factory=tuple)
    mitre_techniques: Tuple[str, ...] = field(default_factory=tuple)
    attack_chain_ids: Tuple[str, ...] = field(default_factory=tuple)
    observations: Tuple[AgentObservation, ...] = field(default_factory=tuple)
    executed_action_ids: Tuple[str, ...] = field(default_factory=tuple)
    current_step: int = 0
    maximum_steps: int = 5
    status: str = AgentStatus.READY
    terminal_reason: Optional[str] = None

    def __post_init__(self) -> None:
        for name in ("scan_id", "target", "asset_id"):
            object.__setattr__(
                self,
                name,
                _required_string(getattr(self, name), name),
            )
        if type(self.authorized) is not bool:
            raise TypeError("authorized must be a boolean")
        if type(self.scan_exists) is not bool:
            raise TypeError("scan_exists must be a boolean")
        findings = tuple(self.findings)
        if len(findings) > MAX_AGENT_FINDINGS:
            raise ValueError("agent state contains too many findings")
        if not all(isinstance(finding, Finding) for finding in findings):
            raise TypeError("findings must contain Finding objects")
        for finding in findings:
            if finding.scan_id != self.scan_id:
                raise ValueError("agent finding belongs to a different scan")
            if finding.asset_id != self.asset_id:
                raise ValueError("agent finding belongs to a different asset")
            if not _same_origin(finding.target, self.target):
                raise ValueError("agent finding belongs to a different target")
        object.__setattr__(self, "findings", findings)
        object.__setattr__(
            self,
            "capabilities",
            _string_tuple(self.capabilities, "capabilities"),
        )
        object.__setattr__(
            self,
            "mitre_techniques",
            _string_tuple(self.mitre_techniques, "mitre_techniques"),
        )
        object.__setattr__(
            self,
            "attack_chain_ids",
            _string_tuple(self.attack_chain_ids, "attack_chain_ids"),
        )
        observations = tuple(self.observations)
        if len(observations) > ABSOLUTE_MAX_AGENT_STEPS:
            raise ValueError("agent state contains too many observations")
        if not all(
            isinstance(observation, AgentObservation)
            for observation in observations
        ):
            raise TypeError("observations must contain AgentObservation objects")
        object.__setattr__(self, "observations", observations)
        object.__setattr__(
            self,
            "executed_action_ids",
            _string_tuple(
                self.executed_action_ids,
                "executed_action_ids",
            ),
        )
        if isinstance(self.current_step, bool) or not isinstance(
            self.current_step,
            int,
        ):
            raise TypeError("current_step must be an integer")
        if not 0 <= self.current_step <= ABSOLUTE_MAX_AGENT_STEPS:
            raise ValueError("current_step is outside the supported range")
        if isinstance(self.maximum_steps, bool) or not isinstance(
            self.maximum_steps,
            int,
        ):
            raise TypeError("maximum_steps must be an integer")
        if not 1 <= self.maximum_steps <= ABSOLUTE_MAX_AGENT_STEPS:
            raise ValueError(
                f"maximum_steps must be between 1 and {ABSOLUTE_MAX_AGENT_STEPS}"
            )
        if self.current_step > self.maximum_steps:
            raise ValueError("current_step cannot exceed maximum_steps")
        if self.status not in AgentStatus.SUPPORTED:
            raise ValueError("unsupported agent status")
        object.__setattr__(
            self,
            "terminal_reason",
            _optional_string(self.terminal_reason, "terminal_reason"),
        )

    @classmethod
    def from_findings(
        cls,
        *,
        scan_id: str,
        target: str,
        asset_id: str,
        authorized: bool,
        findings: Sequence[Finding],
        maximum_steps: int = 5,
        scan_exists: bool = True,
        attack_chain_ids: Sequence[str] = (),
    ) -> "AgentState":
        enriched = tuple(enrich_finding_model(finding) for finding in findings)
        capabilities = list(BASE_CAPABILITIES)
        for finding in enriched:
            if finding.validation_status == ValidationStatus.CONFIRMED:
                capabilities.extend(finding.provides)
        techniques = [
            finding.mitre_technique_id
            for finding in enriched
            if finding.mitre_technique_id
        ]
        return cls(
            scan_id=scan_id,
            target=normalize_origin(target).origin,
            asset_id=asset_id,
            authorized=authorized,
            findings=enriched,
            scan_exists=scan_exists,
            capabilities=tuple(dict.fromkeys(capabilities)),
            mitre_techniques=tuple(dict.fromkeys(techniques)),
            attack_chain_ids=tuple(attack_chain_ids),
            maximum_steps=maximum_steps,
        )

    def finding_by_id(self, finding_id: str) -> Optional[Finding]:
        return next(
            (
                finding
                for finding in self.findings
                if finding.finding_id == finding_id
            ),
            None,
        )

    @property
    def executed_tool_findings(self) -> frozenset[tuple[str, str, tuple]]:
        """Executed (tool, finding, options) fingerprints for deduplication."""
        return frozenset(
            (observation.tool_id, observation.finding_id, observation.options_used)
            for observation in self.observations
            if observation.policy_allowed and observation.finding_id is not None
        )

    def to_dict(self) -> Dict[str, Any]:
        findings = [_finding_view(finding) for finding in self.findings]
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "asset_id": self.asset_id,
            "authorized": self.authorized,
            "scan_exists": self.scan_exists,
            "findings": findings,
            "validation_states": {
                finding["finding_id"]: finding["validation_status"]
                for finding in findings
            },
            "capabilities": list(self.capabilities),
            "mitre_techniques": list(self.mitre_techniques),
            "attack_chain_ids": list(self.attack_chain_ids),
            "observations": [
                observation.to_dict() for observation in self.observations
            ],
            "executed_action_ids": list(self.executed_action_ids),
            "current_step": self.current_step,
            "maximum_steps": self.maximum_steps,
            "status": self.status,
            "terminal_reason": self.terminal_reason,
        }
