"""Fixed registry exposing existing deterministic validators as agent tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Tuple

from app.validation.dispatcher import HANDLERS


class UnknownAgentToolError(LookupError):
    pass


def normalize_vulnerability_type(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


@dataclass(frozen=True)
class AgentToolDefinition:
    tool_id: str
    validator_id: str
    vulnerability_types: Tuple[str, ...]
    description: str
    requires_all: Tuple[str, ...] = field(default_factory=tuple)
    requires_any: Tuple[str, ...] = field(default_factory=tuple)
    provides: Tuple[str, ...] = field(default_factory=tuple)
    automatic_allowed: bool = True

    def __post_init__(self) -> None:
        for name in ("tool_id", "validator_id", "description"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in (
            "vulnerability_types",
            "requires_all",
            "requires_any",
            "provides",
        ):
            values = tuple(getattr(self, name))
            if not all(isinstance(value, str) and value for value in values):
                raise TypeError(f"{name} must contain non-empty strings")
            if name == "vulnerability_types":
                values = tuple(
                    normalize_vulnerability_type(value) for value in values
                )
            object.__setattr__(self, name, tuple(dict.fromkeys(values)))
        if not self.vulnerability_types:
            raise ValueError("vulnerability_types cannot be empty")
        if type(self.automatic_allowed) is not bool:
            raise TypeError("automatic_allowed must be a boolean")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "validator_id": self.validator_id,
            "vulnerability_types": list(self.vulnerability_types),
            "description": self.description,
            "requires_all": list(self.requires_all),
            "requires_any": list(self.requires_any),
            "provides": list(self.provides),
            "automatic_allowed": self.automatic_allowed,
        }


DEFAULT_AGENT_TOOLS = (
    AgentToolDefinition(
        tool_id="validate-sql-injection",
        validator_id="generic-http-sqli",
        vulnerability_types=("sql_injection", "sqli"),
        description="Run the bounded deterministic HTTP SQL injection validator.",
        requires_any=("discovered_services", "reachable_web_application"),
        provides=("application_compromise", "possible_database_access"),
    ),
    AgentToolDefinition(
        tool_id="validate-reflected-xss",
        validator_id="generic-http-reflected-xss",
        vulnerability_types=(
            "cross_site_scripting",
            "reflected_cross_site_scripting",
            "reflected_xss",
            "xss",
        ),
        description="Run the bounded deterministic reflected XSS validator.",
        requires_any=("discovered_services", "reachable_web_application"),
    ),
    AgentToolDefinition(
        tool_id="validate-ssrf",
        validator_id="generic-http-ssrf",
        vulnerability_types=("server_side_request_forgery", "ssrf"),
        description="Run the controlled same-origin SSRF canary validator.",
        requires_any=("discovered_services", "reachable_web_application"),
    ),
    AgentToolDefinition(
        tool_id="validate-exposed-resource",
        validator_id="generic-http-exposed-resource",
        vulnerability_types=(
            "information_disclosure",
            "sensitive_data_exposure",
        ),
        description="Safely retrieve and classify one scanner-supplied resource.",
        requires_any=("discovered_services", "reachable_web_application"),
        provides=("potential_information_exposure",),
    ),
    AgentToolDefinition(
        tool_id="validate-command-execution-simulation",
        validator_id="generic-http-command-execution",
        vulnerability_types=("command_execution",),
        description="Run the fixed controlled-lab command-execution simulation.",
        requires_any=("application_compromise",),
        provides=("command_execution",),
        automatic_allowed=False,
    ),
    AgentToolDefinition(
        tool_id="validate-system-information-discovery-simulation",
        validator_id="controlled-http-system-information-discovery",
        vulnerability_types=("system_information_discovery",),
        description=(
            "Run the fixed loopback-only System Information Discovery "
            "simulation."
        ),
        requires_any=("command_execution",),
        provides=("system_information",),
        automatic_allowed=False,
    ),
)


class AgentToolRegistry:
    """Immutable allowlist of agent-selectable deterministic capabilities."""

    def __init__(
        self,
        definitions: Iterable[AgentToolDefinition] = DEFAULT_AGENT_TOOLS,
    ) -> None:
        records = {}
        for definition in definitions:
            if not isinstance(definition, AgentToolDefinition):
                raise TypeError("agent tools must be AgentToolDefinition objects")
            if definition.tool_id in records:
                raise ValueError(f"duplicate agent tool {definition.tool_id!r}")
            if definition.validator_id not in HANDLERS:
                raise ValueError(
                    f"agent tool references unregistered validator "
                    f"{definition.validator_id!r}"
                )
            records[definition.tool_id] = definition
        self._tools: Mapping[str, AgentToolDefinition] = MappingProxyType(records)

    def require(self, tool_id: str) -> AgentToolDefinition:
        try:
            return self._tools[tool_id]
        except KeyError:
            raise UnknownAgentToolError(
                f"unknown agent tool {tool_id!r}"
            ) from None

    def list_tools(self) -> Tuple[AgentToolDefinition, ...]:
        return tuple(self._tools[key] for key in sorted(self._tools))

    def planner_catalog(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(tool.to_dict() for tool in self.list_tools())
