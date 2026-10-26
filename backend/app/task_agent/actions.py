"""Registered action catalog for the task-centric agent.

Only actions in this catalog may be proposed by the planner.  A Markdown skill
can describe methodology, but it can never become an executable action; it must
resolve to one of these registered ids.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from app.agent.tools import TOOL_REGISTRY, get_tool_catalog
from app.automation import load_all_techniques, technique_catalog
from app.core.config import settings
from app.task_agent.contracts import PlannerDecision, RiskLevel, TaskContract
from app.task_agent.scope import (
    AuthorizedTaskScope,
    TaskScopeError,
    assert_target_in_scope,
    normalize_tool_target,
    target_in_scope,
)


class ActionCatalogError(ValueError):
    """Raised when a planner proposes an unknown or invalid action."""


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    name: str
    description: str
    kind: str
    category: str
    entrypoint: str
    required_arguments: Tuple[str, ...] = ()
    optional_arguments: Tuple[str, ...] = ()
    argument_schema: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 120
    requires_network: bool = True
    risk_level: str = RiskLevel.MEDIUM
    requires_approval: bool = False
    verification: Tuple[str, ...] = ()
    automatic_allowed: bool = True
    available: bool = True
    allowed_target_types: Tuple[str, ...] = (
        "local_file",
        "local_script",
        "docker_lab",
        "private_ip",
        "hostname",
        "test_application",
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("action_id", "name", "description", "kind", "entrypoint"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.risk_level not in RiskLevel.SUPPORTED:
            raise ValueError("invalid action risk level")
        if not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("action timeout must be between 1 and 3600 seconds")

    def planner_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "name": self.name,
            "description": self.description,
            "kind": self.kind,
            "category": self.category,
            "available": self.available,
            "required_arguments": list(self.required_arguments),
            "optional_arguments": list(self.optional_arguments),
            "argument_schema": self.argument_schema,
            "risk_level": self.risk_level,
            "requires_approval": self.requires_approval,
            "requires_network": self.requires_network,
            "verification": list(self.verification),
            "automatic_allowed": self.automatic_allowed,
        }


@dataclass(frozen=True)
class ValidatedAction:
    action: ActionSpec
    decision: PlannerDecision
    arguments: Dict[str, Any]
    target: str
    requires_approval: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": {
                "action_id": self.action.action_id,
                "kind": self.action.kind,
                "entrypoint": self.action.entrypoint,
                "risk_level": self.action.risk_level,
                "timeout_seconds": self.action.timeout_seconds,
                "requires_network": self.action.requires_network,
            },
            "decision": self.decision.to_dict(),
            "arguments": self.arguments,
            "target": self.target,
            "requires_approval": self.requires_approval,
        }


_TOOL_ARGUMENTS: Dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "sqlmap-exploit": (
        ("target",),
        ("parameter", "method", "data", "cookie", "level", "risk", "endpoint"),
    ),
    "hydra-brute": (
        ("target", "service"),
        (
            "port",
            "login_url",
            "username",
            "userlist",
            "passlist",
            "form_params",
            "endpoint",
            "method",
        ),
    ),
    "nikto-scan": (
        ("target",),
        ("port", "ssl", "endpoint"),
    ),
    "gobuster-dir": (
        ("target",),
        ("wordlist", "threads", "extensions", "endpoint"),
    ),
    "ffuf-fuzz": (
        ("target",),
        ("wordlist", "threads", "endpoint"),
    ),
    "katana-crawl": (
        ("target",),
        ("depth", "endpoint"),
    ),
    "nmap-vuln-scripts": (
        ("target",),
        ("ports", "scripts"),
    ),
    "lfi-exploit": (
        ("target",),
        ("parameter", "method", "endpoint"),
    ),
    "xxe-exploit": (
        ("target",),
        ("content_type", "file_to_read", "endpoint"),
    ),
    "metasploit-eternalblue": (
        ("target",),
        ("lhost", "lport", "rhost", "rport", "module"),
    ),
    "metasploit-web-rce": (
        ("target",),
        ("rce_endpoint", "module", "lhost", "lport", "rhost", "rport"),
    ),
    "linpeas-privesc": (
        ("target", "session_id"),
        ("session", "target_session_id"),
    ),
    "winpeas-privesc": (
        ("target", "session_id"),
        ("session", "target_session_id"),
    ),
}

_VALIDATOR_ARGUMENTS = (
    ("target",),
    (
        "endpoint",
        "method",
        "http_method",
        "parameter",
        "parameter_name",
        "parameter_location",
    ),
)

_TECHNIQUE_ARGUMENTS: Dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "T1595": (("target",), ("endpoint", "ports", "http_method", "method")),
    "T1078": (
        ("target",),
        (
            "endpoint",
            "login_url",
            "username",
            "password",
            "service",
            "port",
            "target_session_id",
        ),
    ),
    "T1190": (
        ("target",),
        (
            "endpoint",
            "http_method",
            "method",
            "parameter_name",
            "parameter",
            "parameter_location",
        ),
    ),
    "T1059.004": (
        ("target",),
        ("endpoint", "target_session_id", "command"),
    ),
    "T1068": (("target",), ("target_session_id", "endpoint")),
    "T1548": (("target",), ("target_session_id",)),
    "T1082": (("target",), ("target_session_id",)),
    "T1213": (("target",), ("target_session_id",)),
}

_RISK_BY_ACTION: Dict[str, str] = {
    "tool:nmap-vuln-scripts": RiskLevel.MEDIUM,
    "tool:nikto-scan": RiskLevel.MEDIUM,
    "tool:gobuster-dir": RiskLevel.MEDIUM,
    "tool:ffuf-fuzz": RiskLevel.MEDIUM,
    "tool:katana-crawl": RiskLevel.MEDIUM,
    "tool:sqlmap-exploit": RiskLevel.HIGH,
    "tool:hydra-brute": RiskLevel.HIGH,
    "tool:lfi-exploit": RiskLevel.HIGH,
    "tool:xxe-exploit": RiskLevel.HIGH,
    "tool:metasploit-eternalblue": RiskLevel.HIGH,
    "tool:metasploit-web-rce": RiskLevel.HIGH,
    "tool:linpeas-privesc": RiskLevel.HIGH,
    "tool:winpeas-privesc": RiskLevel.HIGH,
    "technique:T1190": RiskLevel.HIGH,
    "technique:T1068": RiskLevel.HIGH,
    "technique:T1078": RiskLevel.HIGH,
    "technique:T1548": RiskLevel.HIGH,
}

_APPROVAL_ACTION_IDS = {
    "tool:metasploit-eternalblue",
    "tool:metasploit-web-rce",
    "tool:linpeas-privesc",
    "tool:winpeas-privesc",
    "technique:T1068",
    "technique:T1548",
}


def _tool_available(tool_id: str) -> bool:
    if tool_id not in TOOL_REGISTRY:
        return False
    tool = TOOL_REGISTRY[tool_id]
    if not tool.requires_binary:
        return True
    if shutil.which(tool.requires_binary):
        return True
    # Metasploit can be driven through a configured RPC daemon.
    if tool.requires_binary == "msfconsole":
        try:
            from app.agent.tools import _msf_rpc_configured

            return _msf_rpc_configured()
        except Exception:  # noqa: BLE001
            return False
    return False


def _build_tool_specs() -> list[ActionSpec]:
    specs = []
    catalog = {item["tool_id"]: item for item in get_tool_catalog()}
    for tool_id in sorted(TOOL_REGISTRY):
        tool = TOOL_REGISTRY[tool_id]
        required, optional = _TOOL_ARGUMENTS.get(tool_id, (("target",), ()))
        is_validator = tool.category.value == "validator"
        action_id = f"validator:{tool_id}" if is_validator else f"tool:{tool_id}"
        risk = _RISK_BY_ACTION.get(action_id, RiskLevel.LOW if is_validator else RiskLevel.MEDIUM)
        repository = {
            "description": tool.description,
            "vulnerability_types": list(tool.vuln_types),
            "requires_binary": tool.requires_binary,
            "category": tool.category.value,
        }
        specs.append(
            ActionSpec(
                action_id=action_id,
                name=tool.name,
                description=tool.description,
                kind="validator" if is_validator else "tool",
                category=tool.category.value,
                entrypoint="app.agent.tools:execute_tool",
                required_arguments=required,
                optional_arguments=optional,
                argument_schema=_schema_for(required, optional),
                timeout_seconds=180 if tool_id in {"nmap-vuln-scripts", "nikto-scan"} else 120,
                requires_network=not is_validator or tool_id not in {
                    "validate-command-execution-simulation",
                    "validate-system-information-discovery-simulation",
                },
                risk_level=risk,
                requires_approval=action_id in _APPROVAL_ACTION_IDS,
                verification=_verification_for(tool_id),
                automatic_allowed=True,
                available=bool(catalog.get(tool_id, {}).get("available", _tool_available(tool_id))),
                allowed_target_types=(
                    "local_file",
                    "local_script",
                )
                if tool_id in {
                    "linpeas-privesc",
                    "winpeas-privesc",
                }
                else (
                    "private_ip",
                    "hostname",
                    "test_application",
                    "docker_lab",
                ),
                metadata=repository,
            )
        )
    return specs


def _build_technique_specs() -> list[ActionSpec]:
    specs = []
    for item in technique_catalog():
        technique_id = item["technique_id"]
        action_id = f"technique:{technique_id}"
        required, optional = _TECHNIQUE_ARGUMENTS.get(technique_id, (("target",), ()))
        specs.append(
            ActionSpec(
                action_id=action_id,
                name=item.get("name", technique_id),
                description=item.get("description", "MITRE technique"),
                kind="technique",
                category=item.get("tactic", "mitre-technique"),
                entrypoint="app.automation.runner:run_technique_execution",
                required_arguments=required,
                optional_arguments=optional,
                argument_schema=_schema_for(required, optional),
                timeout_seconds=180,
                requires_network=True,
                risk_level=_RISK_BY_ACTION.get(action_id, RiskLevel.MEDIUM),
                requires_approval=action_id in _APPROVAL_ACTION_IDS,
                verification=("structured technique result", "evidence", "capability claim"),
                automatic_allowed=bool(item.get("automatic_allowed", True)),
                available=True,
                allowed_target_types=(
                    "private_ip",
                    "hostname",
                    "test_application",
                    "docker_lab",
                ),
                metadata={
                    "technique_id": technique_id,
                    "requires_all": list(item.get("requires_all", [])),
                    "requires_any": list(item.get("requires_any", [])),
                    "provides": list(item.get("provides", [])),
                    "vuln_types": list(item.get("vuln_types", [])),
                },
            )
        )
    return specs


def _build_script_specs() -> list[ActionSpec]:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "validate_planner_dataset.py"
    return [
        ActionSpec(
            action_id="script:validate-planner-dataset",
            name="Planner dataset validator",
            description=(
                "Validate a planner JSONL dataset against the strict planner "
                "contract and write a deterministic JSON report."
            ),
            kind="script",
            category="analysis",
            entrypoint="backend/scripts/validate_planner_dataset.py",
            required_arguments=("path",),
            optional_arguments=("output", "max_records"),
            argument_schema=_schema_for(
                ("path",), ("output", "max_records")
            ),
            timeout_seconds=60,
            requires_network=False,
            risk_level=RiskLevel.LOW,
            verification=("report file exists", "record counts", "schema errors"),
            available=script_path.is_file(),
            allowed_target_types=("local_file", "local_script"),
            metadata={"script_path": str(script_path)},
        ),
        ActionSpec(
            action_id="script:inspect-json",
            name="JSON artifact inspector",
            description=(
                "Read a bounded JSON artifact produced by an earlier step and "
                "return its top-level structure.  It never executes content."
            ),
            kind="script",
            category="analysis",
            entrypoint="builtin:inspect_json",
            required_arguments=("path",),
            optional_arguments=("max_bytes",),
            argument_schema=_schema_for(("path",), ("max_bytes",)),
            timeout_seconds=15,
            requires_network=False,
            risk_level=RiskLevel.LOW,
            verification=("file exists", "JSON parses", "artifact hash recorded"),
            available=True,
            allowed_target_types=("local_file", "local_script", "private_ip", "hostname", "test_application"),
        ),
    ]


def _schema_for(required: Sequence[str], optional: Sequence[str]) -> Dict[str, Any]:
    properties: Dict[str, Any] = {}
    for name in (*required, *optional):
        if name in {"port", "rport", "lport", "level", "risk", "threads", "depth", "max_records", "max_bytes"}:
            properties[name] = {"type": "integer"}
        elif name in {"ssl"}:
            properties[name] = {"type": "boolean"}
        elif name in {"ports"}:
            properties[name] = {"type": "string", "description": "nmap syntax, e.g. 80,443,8000-8100"}
        elif name in {"cookie", "password", "passlist", "userlist"}:
            properties[name] = {"type": "string", "sensitive": True}
        else:
            properties[name] = {"type": "string"}
    return {
        "type": "object",
        "required": list(required),
        "additionalProperties": False,
        "properties": properties,
    }


def _verification_for(tool_id: str) -> tuple[str, ...]:
    mapping = {
        "sqlmap-exploit": ("database enumeration in structured output", "non-empty response evidence"),
        "hydra-brute": ("credential pair in structured output", "target session opens"),
        "nikto-scan": ("parsed findings", "HTTP response evidence"),
        "gobuster-dir": ("parsed paths", "HTTP status evidence"),
        "ffuf-fuzz": ("parsed paths", "HTTP status evidence"),
        "katana-crawl": ("parsed URLs", "HTTP status evidence"),
        "nmap-vuln-scripts": ("NSE vulnerability signal", "service evidence"),
        "lfi-exploit": ("file marker in response", "response evidence"),
        "xxe-exploit": ("file marker in response", "response evidence"),
        "metasploit-eternalblue": ("session opened", "session evidence"),
        "metasploit-web-rce": ("session opened", "session evidence"),
        "linpeas-privesc": ("privilege marker", "session evidence"),
        "winpeas-privesc": ("privilege marker", "session evidence"),
    }
    if tool_id in mapping:
        return mapping[tool_id]
    if tool_id.startswith("validate-"):
        return ("validator status is confirmed/rejected", "HTTP response evidence")
    return ("structured result", "evidence")


class ActionCatalog:
    """Immutable registry of every action a task planner may select."""

    def __init__(self, actions: Optional[Iterable[ActionSpec]] = None) -> None:
        if actions is None:
            load_all_techniques()
            actions = [*_build_tool_specs(), *_build_technique_specs(), *_build_script_specs()]
        records: Dict[str, ActionSpec] = {}
        for action in actions:
            if action.action_id in records:
                raise ValueError(f"duplicate action id {action.action_id!r}")
            records[action.action_id] = action
        self._actions = dict(sorted(records.items()))

    def require(self, action_id: str) -> ActionSpec:
        try:
            return self._actions[action_id]
        except KeyError as exc:
            raise ActionCatalogError(f"unknown registered action {action_id!r}") from exc

    def list(self) -> Tuple[ActionSpec, ...]:
        return tuple(self._actions.values())

    def available(self) -> Tuple[ActionSpec, ...]:
        return tuple(action for action in self._actions.values() if action.available)

    def planner_catalog(self, task: TaskContract) -> Tuple[Dict[str, Any], ...]:
        permitted = set(task.permitted_actions)
        allow_all = "*" in permitted or "all" in permitted
        rows = []
        for action in self._actions.values():
            if not action.available or not action.automatic_allowed:
                continue
            if not allow_all and not _permitted(action.action_id, permitted):
                continue
            if task.target_type not in action.allowed_target_types:
                continue
            rows.append(action.planner_dict())
        return tuple(rows)

    def validate(
        self,
        task: TaskContract,
        decision: PlannerDecision,
        scope: AuthorizedTaskScope,
    ) -> ValidatedAction:
        if decision.decision == "finish":
            if decision.action_id not in {"finish", "done", "complete"}:
                raise ActionCatalogError("finish decision must use action_id=finish")
            if not target_in_scope(decision.target, scope):
                raise ActionCatalogError("finish target is outside the task scope")
            return ValidatedAction(
                action=self.require("script:inspect-json")
                if "script:inspect-json" in self._actions
                else _finish_spec(),
                decision=decision,
                arguments={},
                target=decision.target,
                requires_approval=False,
            )
        if decision.decision == "report":
            if decision.action_id not in {"report", "reporter"}:
                raise ActionCatalogError("report decision must use action_id=report")
            if not target_in_scope(decision.target, scope):
                raise ActionCatalogError("report target is outside the task scope")
            return ValidatedAction(
                action=_report_spec(),
                decision=decision,
                arguments=dict(decision.arguments),
                target=decision.target,
                requires_approval=False,
            )
        if decision.decision == "generate_code":
            if not _permitted("generate_code", set(task.permitted_actions)) and "*" not in task.permitted_actions and "all" not in task.permitted_actions:
                raise ActionCatalogError("generated code is not permitted by this task")
            if decision.action_id not in {"generate_code", "code", "generated-code"}:
                raise ActionCatalogError(
                    "generate_code decision must use action_id=generate_code"
                )
            if not target_in_scope(decision.target, scope):
                raise ActionCatalogError("code target is outside the task scope")
            return ValidatedAction(
                action=_generated_code_spec(),
                decision=decision,
                arguments=dict(decision.arguments),
                target=decision.target,
                requires_approval=(
                    task.approval_required
                    or settings.TASK_AGENT_APPROVAL_MODE == "all"
                ),
            )
        if decision.decision == "inspect_artifact":
            if not _permitted("inspect_artifact", set(task.permitted_actions)) and "*" not in task.permitted_actions and "all" not in task.permitted_actions:
                raise ActionCatalogError("artifact inspection is not permitted")
            if decision.action_id not in {"inspect_artifact", "artifact"}:
                raise ActionCatalogError(
                    "inspect_artifact decision must use action_id=inspect_artifact"
                )
            return ValidatedAction(
                action=self.require("script:inspect-json"),
                decision=decision,
                arguments=dict(decision.arguments),
                target=decision.target,
                requires_approval=False,
            )
        if decision.decision != "run_registered_action":
            raise ActionCatalogError("unsupported decision")
        action = self.require(decision.action_id)
        if not action.available:
            raise ActionCatalogError("the requested action is unavailable on this host")
        if not action.automatic_allowed:
            raise ActionCatalogError("the requested action requires explicit operator opt-in")
        if not _permitted(action.action_id, set(task.permitted_actions)) and "*" not in task.permitted_actions and "all" not in task.permitted_actions:
            raise ActionCatalogError("the requested action is not permitted by this task")
        if task.target_type not in action.allowed_target_types:
            raise ActionCatalogError("the requested action does not support this target type")
        if not target_in_scope(decision.target, scope):
            raise ActionCatalogError("the requested action target is outside the task scope")
        if action.requires_network and task.network_policy == "none":
            raise ActionCatalogError(
                "network actions require network_policy lab or allowlisted"
            )
        arguments = _normalize_arguments(action, decision.arguments, scope)
        requires_approval = (
            action.requires_approval
            or decision.requires_approval
            or task.approval_required
            or settings.TASK_AGENT_APPROVAL_MODE == "all"
            or (
                settings.TASK_AGENT_APPROVAL_MODE == "high_risk"
                and action.risk_level == RiskLevel.HIGH
            )
        )
        return ValidatedAction(
            action=action,
            decision=decision,
            arguments=arguments,
            target=decision.target,
            requires_approval=requires_approval,
        )


def _finish_spec() -> ActionSpec:
    return ActionSpec(
        action_id="finish",
        name="Finish task",
        description="Finish the task and report the verified outcome.",
        kind="control",
        category="control",
        entrypoint="builtin:finish",
        requires_network=False,
        risk_level=RiskLevel.LOW,
        available=True,
    )


def _report_spec() -> ActionSpec:
    return ActionSpec(
        action_id="report",
        name="Generate report",
        description="Generate JSON and Markdown reports from persisted evidence.",
        kind="report",
        category="reporting",
        entrypoint="app.task_agent.reporter:TaskReporter",
        requires_network=False,
        risk_level=RiskLevel.LOW,
        available=True,
    )


def _generated_code_spec() -> ActionSpec:
    return ActionSpec(
        action_id="generate_code",
        name="Generate bounded analysis code",
        description="Generate Python code and run it in the isolated worker.",
        kind="generated_code",
        category="analysis",
        entrypoint="app.task_agent.coder:Coder",
        requires_network=False,
        risk_level=RiskLevel.LOW,
        available=True,
        allowed_target_types=(
            "local_file",
            "local_script",
            "private_ip",
            "hostname",
            "test_application",
        ),
    )


def _permitted(action_id: str, permitted: set[str]) -> bool:
    if not permitted:
        return False
    if action_id in permitted:
        return True
    for prefix in ("tool", "technique", "validator", "script"):
        if f"{prefix}:*" in permitted and action_id.startswith(f"{prefix}:"):
            return True
    return False


def _normalize_arguments(
    action: ActionSpec,
    values: Mapping[str, Any],
    scope: AuthorizedTaskScope,
) -> Dict[str, Any]:
    if not isinstance(values, Mapping):
        raise ActionCatalogError("arguments must be an object")
    unknown = set(values) - set(action.required_arguments) - set(action.optional_arguments)
    if unknown:
        raise ActionCatalogError(
            "arguments contain unregistered keys: " + ", ".join(sorted(unknown))
        )
    missing = set(action.required_arguments) - set(values)
    if missing:
        raise ActionCatalogError(
            "arguments are missing required keys: " + ", ".join(sorted(missing))
        )
    normalized: Dict[str, Any] = {}
    for key, value in values.items():
        if key in {"target", "endpoint", "login_url"} and isinstance(value, str):
            if value and key == "target":
                assert_target_in_scope(value, scope)
            normalized[key] = value.strip()
            continue
        if key in {"port", "rport", "lport", "level", "risk", "threads", "depth", "max_records", "max_bytes"}:
            try:
                normalized[key] = int(value)
            except (TypeError, ValueError) as exc:
                raise ActionCatalogError(f"argument {key} must be an integer") from exc
            continue
        if key == "ssl":
            if type(value) is not bool:
                raise ActionCatalogError("argument ssl must be a boolean")
            normalized[key] = value
            continue
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            raise ActionCatalogError(f"argument {key} must be a scalar")
        normalized[key] = value
    target = normalized.get("target") or scope.target
    if action.requires_network:
        if action.kind in {"tool", "technique"}:
            try:
                if action.category in {"recon", "real_tool", "mitre-technique"} and action.action_id in {
                    "tool:nmap-vuln-scripts",
                    "tool:hydra-brute",
                    "tool:linpeas-privesc",
                    "tool:winpeas-privesc",
                }:
                    host_port = normalize_tool_target(target, kind="hostport" if action.action_id == "tool:hydra-brute" else "host")
                    if ":" in host_port and action.action_id == "tool:hydra-brute":
                        host, port_text = host_port.rsplit(":", 1)
                        normalized.setdefault("target", host)
                        normalized.setdefault("port", int(port_text))
                elif action.kind == "tool":
                    normalized.setdefault("target", normalize_tool_target(target, kind="web"))
            except (TaskScopeError, ValueError) as exc:
                raise ActionCatalogError(str(exc)) from exc
        ports = normalized.get("ports")
        if isinstance(ports, str) and ports:
            _validate_port_expression(ports, scope)
        for key in ("port", "rport", "lport"):
            if key in normalized and key != "lport":
                if normalized[key] not in scope.allowed_ports:
                    raise ActionCatalogError(f"port {normalized[key]} is not authorized")
    return normalized


def _validate_port_expression(value: str, scope: AuthorizedTaskScope) -> None:
    authorized = set(scope.allowed_ports)
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = (int(item) for item in part.split("-", 1))
            except ValueError as exc:
                raise ActionCatalogError("invalid port range") from exc
            if start > end or end - start > 1024:
                raise ActionCatalogError("invalid port range")
            for port in range(start, end + 1):
                if authorized and port not in authorized:
                    raise ActionCatalogError(f"port {port} is not authorized")
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise ActionCatalogError("invalid port") from exc
            if authorized and port not in authorized:
                raise ActionCatalogError(f"port {port} is not authorized")


__all__ = [
    "ActionCatalog",
    "ActionCatalogError",
    "ActionSpec",
    "ValidatedAction",
    "target_in_scope",
]
