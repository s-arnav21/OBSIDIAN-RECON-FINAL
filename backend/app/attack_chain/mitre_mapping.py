"""Small, evidence-conscious MITRE ATT&CK and environmental-fact registry."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional

from app.models.finding import Finding


def _normalize_vulnerability_type(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_")


@dataclass(frozen=True)
class TechniqueDefinition:
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    requires_all: List[str] = field(default_factory=list)
    requires_any: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    vulnerability_types: List[str] = field(default_factory=list)
    cwe_hints: List[str] = field(default_factory=list)
    owasp_hints: List[str] = field(default_factory=list)

    @property
    def requires(self) -> List[str]:
        """Compatibility view of all declared prerequisite capabilities."""
        return [*self.requires_all, *self.requires_any]

    @property
    def vuln_types(self) -> List[str]:
        """Compatibility alias for the original mapping field."""
        return self.vulnerability_types


@dataclass(frozen=True)
class EnvironmentalFactDefinition:
    """Capabilities observed by Obsidian, not adversary ATT&CK behavior."""

    vulnerability_types: List[str]
    provides: List[str]
    requires_all: List[str] = field(default_factory=list)
    requires_any: List[str] = field(default_factory=list)


TECHNIQUE_DEFINITIONS: Dict[str, TechniqueDefinition] = {
    "T1595": TechniqueDefinition(
        technique_id="T1595",
        technique_name="Active Scanning",
        tactic="Reconnaissance",
        description=(
            "Observed adversary active scanning. Obsidian's own scanner activity "
            "does not map to this technique."
        ),
        requires_any=["unauthenticated"],
        provides=["adversary_reconnaissance_observed"],
        vulnerability_types=["observed_adversary_active_scanning"],
    ),
    "T1190": TechniqueDefinition(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description=(
            "A validated exploitable condition in a reachable public-facing "
            "application."
        ),
        requires_any=[
            "discovered_services",
            "reachable_web_application",
        ],
        provides=[
            "application_compromise",
            "possible_database_access",
        ],
        vulnerability_types=[
            "sql_injection",
            "sqli",
            "rce",
            "remote_code_execution",
            "command_injection",
            "deserialization",
        ],
        cwe_hints=["CWE-89", "CWE-78", "CWE-502"],
        owasp_hints=["A03:2021"],
    ),
    "T1059.004": TechniqueDefinition(
        technique_id="T1059.004",
        technique_name="Command and Scripting Interpreter: Unix Shell",
        tactic="Execution",
        description=(
            "Validated deterministic Unix-shell interpretation after an "
            "application compromise."
        ),
        requires_any=["application_compromise"],
        provides=["command_execution"],
        vulnerability_types=[
            "command_execution",
            "unix_shell_command_execution",
        ],
        cwe_hints=["CWE-78"],
        owasp_hints=["A03:2021"],
    ),
    "T1082": TechniqueDefinition(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        description=(
            "Discovery of operating-system or hardware information from a "
            "compromised execution context."
        ),
        requires_any=["command_execution"],
        provides=["system_information"],
        vulnerability_types=["system_information_discovery"],
    ),
    "T1078": TechniqueDefinition(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Initial Access / Persistence / Privilege Escalation / Defense Evasion",
        description="Validated use or availability of a legitimate account.",
        requires_any=[
            "discovered_services",
            "reachable_login_service",
        ],
        provides=[
            "authenticated_session",
            "credential_access",
        ],
        vulnerability_types=[
            "default_credentials",
            "weak_credentials",
            "valid_accounts",
        ],
        cwe_hints=["CWE-521"],
        owasp_hints=["A07:2021"],
    ),
    "T1213": TechniqueDefinition(
        technique_id="T1213",
        technique_name="Data from Information Repositories",
        tactic="Collection",
        description=(
            "Validated access to data held in an information repository. "
            "Generic disclosure alone is insufficient."
        ),
        requires_any=[
            "application_compromise",
            "possible_database_access",
            "authenticated_session",
        ],
        provides=[
            "repository_data_access",
            "credential_material",
        ],
        vulnerability_types=[
            "database_repository_access",
            "information_repository_access",
            "database_dump",
        ],
        cwe_hints=["CWE-200", "CWE-284"],
        owasp_hints=["A01:2021", "A02:2021"],
    ),
}


ENVIRONMENTAL_FACT_DEFINITIONS: List[EnvironmentalFactDefinition] = [
    EnvironmentalFactDefinition(
        vulnerability_types=[
            "port_scan",
            "service_scan",
            "network_scan",
            "nmap_scan",
        ],
        provides=[
            "discovered_hosts",
            "discovered_open_ports",
            "discovered_services",
        ],
    ),
    EnvironmentalFactDefinition(
        vulnerability_types=["nuclei_scan"],
        provides=[
            "reachable_web_application",
            "scanner_observed_web_condition",
        ],
    ),
]

CONSERVATIVE_UNMAPPED_CAPABILITIES: Dict[str, List[str]] = {
    "information_disclosure": ["potential_information_exposure"],
    "sensitive_data_exposure": ["potential_information_exposure"],
}


def get_environmental_fact(
    vulnerability_type: str,
) -> Optional[EnvironmentalFactDefinition]:
    normalized = _normalize_vulnerability_type(vulnerability_type)
    for definition in ENVIRONMENTAL_FACT_DEFINITIONS:
        if normalized in definition.vulnerability_types:
            return definition
    return None


def is_environmental_fact(vulnerability_type: str) -> bool:
    return get_environmental_fact(vulnerability_type) is not None


def map_vulnerability_to_technique(
    vulnerability_type: str,
) -> Optional[TechniqueDefinition]:
    """Return a supported mapping, or None rather than fabricating one."""
    normalized = _normalize_vulnerability_type(vulnerability_type)
    for definition in TECHNIQUE_DEFINITIONS.values():
        if normalized in definition.vulnerability_types:
            return definition
    return None


def get_technique(technique_id: str) -> Optional[TechniqueDefinition]:
    return TECHNIQUE_DEFINITIONS.get(technique_id)


def techniques_unlocked_by(capability: str) -> List[TechniqueDefinition]:
    return [
        definition
        for definition in TECHNIQUE_DEFINITIONS.values()
        if capability in definition.requires_all
        or capability in definition.requires_any
    ]


def enrich_finding_model(finding: Finding) -> Finding:
    """Return a Finding enriched from the authoritative local registries."""
    environmental = get_environmental_fact(finding.vulnerability_type)
    if environmental is not None:
        return replace(
            finding,
            mitre_tactic=None,
            mitre_technique_id=None,
            mitre_technique_name=None,
            requires_all=(
                finding.requires_all or environmental.requires_all
            ),
            requires_any=(
                finding.requires_any or environmental.requires_any
            ),
            provides=finding.provides or environmental.provides,
        )

    technique = map_vulnerability_to_technique(finding.vulnerability_type)
    if technique is None:
        # Explicit unsupported mappings are not trusted by the engine.
        conservative_provides = CONSERVATIVE_UNMAPPED_CAPABILITIES.get(
            _normalize_vulnerability_type(finding.vulnerability_type)
        )
        return replace(
            finding,
            mitre_tactic=None,
            mitre_technique_id=None,
            mitre_technique_name=None,
            provides=(
                conservative_provides
                if conservative_provides is not None
                else finding.provides
            ),
        )

    has_prerequisites = bool(
        finding.requires_all
        or finding.requires_any
        or finding.requires
    )
    return replace(
        finding,
        mitre_tactic=technique.tactic,
        mitre_technique_id=technique.technique_id,
        mitre_technique_name=technique.technique_name,
        requires_all=(
            finding.requires_all
            if has_prerequisites
            else technique.requires_all
        ),
        requires_any=(
            finding.requires_any
            if has_prerequisites
            else technique.requires_any
        ),
        provides=finding.provides or technique.provides,
    )


def enrich_finding(finding_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Backward-compatible dictionary enrichment for legacy fixtures."""
    enriched = dict(finding_dict)
    vulnerability_type = enriched.get("vulnerability_type", "")
    if not vulnerability_type:
        return enriched

    environmental = get_environmental_fact(vulnerability_type)
    if environmental is not None:
        enriched["mitre_tactic"] = None
        enriched["mitre_technique_id"] = None
        enriched["mitre_technique_name"] = None
        enriched.setdefault("requires_all", environmental.requires_all)
        enriched.setdefault("requires_any", environmental.requires_any)
        enriched.setdefault("provides", environmental.provides)
        return enriched

    technique = map_vulnerability_to_technique(vulnerability_type)
    if technique is None:
        enriched["mitre_tactic"] = None
        enriched["mitre_technique_id"] = None
        enriched["mitre_technique_name"] = None
        conservative_provides = CONSERVATIVE_UNMAPPED_CAPABILITIES.get(
            _normalize_vulnerability_type(vulnerability_type)
        )
        if conservative_provides is not None:
            enriched["provides"] = conservative_provides
        return enriched

    enriched["mitre_tactic"] = technique.tactic
    enriched["mitre_technique_id"] = technique.technique_id
    enriched["mitre_technique_name"] = technique.technique_name
    if not any(
        enriched.get(name)
        for name in ("requires_all", "requires_any", "requires")
    ):
        enriched["requires_all"] = technique.requires_all
        enriched["requires_any"] = technique.requires_any
    enriched.setdefault("provides", technique.provides)
    return enriched


def all_techniques() -> List[TechniqueDefinition]:
    return list(TECHNIQUE_DEFINITIONS.values())
