"""Deterministic planner-training dataset for Obsidian Recon.

The dataset is a set of JSONL records. Each record is exactly the planner's
input plus the exact output it should produce::

    {
      "scenario_id": str,
      "step_index": int,
      "state": {...},             # only _STATE_FIELDS + findings/observations
      "available_tools": [...],   # only _TOOL_FIELDS entries
      "output": {...},            # {"decision": "action"|"complete", ...}
      "supervision": {...}        # NOT sent to the planner
    }

``supervision`` records the deterministic policy outcome and the plausible but
rejected candidates (duplicate, prerequisite, step-limit, unknown tool, invalid
reference). It exists for auditing and never appears in ``state`` or
``available_tools``.

Only MITRE ATT&CK Enterprise techniques are represented. Raw evidence, CVSS
vectors, CWE/OWASP codes, credentials, sessions, commands, and request/response
state are excluded from the planner-facing fields.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import urlparse

from app.agent.llm_planner import (
    _FINDING_FIELDS,
    _OBSERVATION_FIELDS,
    _STATE_FIELDS,
    _TOOL_FIELDS,
)
from app.agent.tools import (
    AgentToolRegistry,
    get_tool_catalog,
    normalize_vulnerability_type,
)
from app.automation import technique_tool_catalog


# The eight MITRE ATT&CK Enterprise techniques this dataset teaches.
TECHNIQUE_IDS: Tuple[str, ...] = (
    "T1595",
    "T1190",
    "T1059.004",
    "T1082",
    "T1078",
    "T1213",
    "T1548",
    "T1068",
)

TECHNIQUE_NAMES: Dict[str, str] = {
    "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing Application",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1082": "System Information Discovery",
    "T1078": "Valid Accounts",
    "T1213": "Data from Information Repositories",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1068": "Exploitation for Privilege Escalation",
}

TARGET = "http://10.20.30.40"
SCAN_ID = "scan-train-001"
ASSET_ID = "asset-train-001"
ATTACK_CHAIN_ID = "AC-TRAIN-001"

TOP_LEVEL_FIELDS = frozenset({
    "scenario_id",
    "step_index",
    "state",
    "available_tools",
    "output",
    "supervision",
})
ACTION_FIELDS = frozenset({
    "action_id",
    "tool_id",
    "scan_id",
    "asset_id",
    "finding_id",
    "target",
    "reason",
    "expected_capabilities",
    "options",
})
SUPERVISION_FIELDS = frozenset({
    "technique_id",
    "policy_outcome",
    "policy_code",
    "rejected_candidates",
    "notes",
})
ALLOWED_OPTION_KEYS = frozenset({
    "endpoint",
    "http_method",
    "parameter_name",
    "parameter_location",
})
REQUIRED_NEGATIVE_CODES = frozenset({
    "denied_duplicate",
    "denied_invalid_reference",
    "denied_prerequisite",
    "denied_step_limit",
    "denied_unknown_tool",
})

# Keys that must never enter the planner-facing views. The list is exact-key
# based, so capability names such as "authenticated_session" remain allowed.
FORBIDDEN_KEYS = frozenset({
    "authorization",
    "command",
    "commands",
    "cookie",
    "cookies",
    "cwe",
    "cwe_id",
    "cvss",
    "cvss_score",
    "cvss_vector",
    "evidence",
    "evidence_refs",
    "http_request_context",
    "http_response",
    "owasp",
    "owasp_category",
    "password",
    "passwords",
    "payload",
    "raw",
    "raw_finding",
    "raw_finding_ref",
    "raw_request",
    "raw_response",
    "request_headers",
    "response_body",
    "secret",
    "session_id",
    "session_token",
    "shell",
})
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"CWE-\d+", re.IGNORECASE),
    re.compile(r"CVSS", re.IGNORECASE),
    re.compile(r"\bOWASP\b", re.IGNORECASE),
    re.compile(r"\bCAPEC-\d+", re.IGNORECASE),
    re.compile(r"\bCVE-\d{4}-\d+", re.IGNORECASE),
    re.compile(r"\bD3FEND\b", re.IGNORECASE),
    re.compile(r"\bATLAS\b", re.IGNORECASE),
    re.compile(r"PRE-ATT&CK", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+-----"),
)


class DatasetValidationError(ValueError):
    """Raised when a planner dataset record violates the contract."""


# ---------------------------------------------------------------------------
# Projection helpers
# ---------------------------------------------------------------------------

def _only(value: Mapping[str, Any], fields: Sequence[str]) -> Dict[str, Any]:
    return {field: value[field] for field in fields if field in value}


def _finding(
    *,
    finding_id: str,
    vulnerability_type: str,
    severity: str,
    validation_status: str,
    endpoint: str,
    mitre_technique_id: str,
    mitre_technique_name: str,
    mitre_tactic: str,
    validator_id: str = None,
    http_method: str = "GET",
    parameter_name: str = None,
    parameter_location: str = None,
    validation_confidence: float = 0.0,
    requires_all: Sequence[str] = (),
    requires_any: Sequence[str] = (),
    provides: Sequence[str] = (),
) -> Dict[str, Any]:
    finding = {
        "finding_id": finding_id,
        "scan_id": SCAN_ID,
        "asset_id": ASSET_ID,
        "target": TARGET,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "validator_id": validator_id,
        "endpoint": endpoint,
        "http_method": http_method,
        "parameter_name": parameter_name,
        "parameter_location": parameter_location,
        "validation_status": validation_status,
        "validation_confidence": validation_confidence,
        "mitre_technique_id": mitre_technique_id,
        "mitre_technique_name": mitre_technique_name,
        "mitre_tactic": mitre_tactic,
        "requires_all": list(requires_all),
        "requires_any": list(requires_any),
        "provides": list(provides),
    }
    return _only(finding, _FINDING_FIELDS)


def _observation(
    *,
    action_id: str,
    tool_id: str,
    finding_id: str,
    summary: str,
    validation_status: str = None,
    capabilities_gained: Sequence[str] = (),
    options_used: Mapping[str, Any] = None,
    validation_decision: str = None,
    observed_http_status: int = None,
    observed_response_length: int = None,
    detection_methods: Sequence[str] = (),
    error_category: str = None,
) -> Dict[str, Any]:
    observation = {
        "action_id": action_id,
        "tool_id": tool_id,
        "finding_id": finding_id,
        "policy_decision": "allowed",
        "policy_allowed": True,
        "execution_status": "completed",
        "validation_status": validation_status,
        "capabilities_gained": list(capabilities_gained),
        "summary": summary,
        "error_category": error_category,
        "validation_decision": validation_decision,
        "detection_methods": list(detection_methods),
        "observed_http_status": observed_http_status,
        "observed_response_length": observed_response_length,
        "waf_or_filter_interference": False,
        "options_used": [
            list(item) for item in sorted((options_used or {}).items())
        ],
    }
    return _only(observation, _OBSERVATION_FIELDS)


def _state(
    *,
    findings: Sequence[Mapping[str, Any]],
    capabilities: Sequence[str],
    mitre_techniques: Sequence[str],
    observations: Sequence[Mapping[str, Any]] = (),
    executed_action_ids: Sequence[str] = (),
    current_step: int = 0,
    maximum_steps: int = 5,
) -> Dict[str, Any]:
    finding_list = [_only(item, _FINDING_FIELDS) for item in findings]
    state = {
        "scan_id": SCAN_ID,
        "target": TARGET,
        "asset_id": ASSET_ID,
        "authorized": True,
        "scan_exists": True,
        "validation_states": {
            item["finding_id"]: item["validation_status"]
            for item in finding_list
        },
        "capabilities": list(dict.fromkeys(capabilities)),
        "mitre_techniques": list(dict.fromkeys(mitre_techniques)),
        "attack_chain_ids": [ATTACK_CHAIN_ID],
        "executed_action_ids": list(executed_action_ids),
        "current_step": current_step,
        "maximum_steps": maximum_steps,
        "status": "running",
        "terminal_reason": None,
        "findings": finding_list,
        "observations": [
            _only(item, _OBSERVATION_FIELDS) for item in observations
        ],
    }
    projected = _only(state, _STATE_FIELDS)
    projected["findings"] = state["findings"]
    projected["observations"] = state["observations"]
    return projected


def _action(
    *,
    action_id: str,
    tool_id: str,
    finding_id: str,
    reason: str,
    expected_capabilities: Sequence[str] = (),
    options: Mapping[str, Any] = None,
) -> Dict[str, Any]:
    action = {
        "action_id": action_id,
        "tool_id": tool_id,
        "scan_id": SCAN_ID,
        "asset_id": ASSET_ID,
        "finding_id": finding_id,
        "target": TARGET,
        "reason": reason,
        "expected_capabilities": list(expected_capabilities),
        "options": dict(options or {}),
    }
    return _only(action, ACTION_FIELDS)


def _reject(
    *,
    tool_id: str,
    finding_id: str,
    code: str,
    reason: str,
    options: Mapping[str, Any] = None,
    scan_id: str = None,
) -> Dict[str, Any]:
    candidate = {
        "tool_id": tool_id,
        "finding_id": finding_id,
        "scan_id": scan_id or SCAN_ID,
        "asset_id": ASSET_ID,
        "target": TARGET,
        "options": dict(options or {}),
    }
    return {"candidate": candidate, "code": code, "reason": reason}


def _supervision(
    *,
    technique_id: str,
    output: Mapping[str, Any],
    rejected: Sequence[Mapping[str, Any]] = (),
    notes: Sequence[str] = (),
) -> Dict[str, Any]:
    is_action = output.get("decision") == "action"
    supervision = {
        "technique_id": technique_id,
        "policy_outcome": "allowed" if is_action else "complete",
        "policy_code": "allowed" if is_action else "completed",
        "rejected_candidates": list(rejected),
        "notes": list(notes),
    }
    return _only(supervision, SUPERVISION_FIELDS)


def _complete() -> Dict[str, Any]:
    return {"decision": "complete", "action": None}


def _record(
    *,
    scenario_id: str,
    state: Mapping[str, Any],
    tools: Sequence[Mapping[str, Any]],
    output: Mapping[str, Any],
    supervision: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "step_index": int(state["current_step"]),
        "state": dict(state),
        "available_tools": [dict(tool) for tool in tools],
        "output": dict(output),
        "supervision": dict(supervision),
    }


# ---------------------------------------------------------------------------
# Tool catalog
# ---------------------------------------------------------------------------

def default_available_tools() -> List[Dict[str, Any]]:
    """Every registered tool plus every technique script, planner-shaped.

    Externally-installed tools are marked available so the training examples
    can teach escalation. The validator still checks registration and the
    advertised option keys, not local binary presence.
    """
    registry = AgentToolRegistry()
    flat = {tool["tool_id"]: tool for tool in get_tool_catalog()}
    tools: List[Dict[str, Any]] = []
    for definition in registry.planner_catalog():
        tool_id = definition["tool_id"]
        base = flat.get(tool_id, {})
        vuln_types = list(definition["vulnerability_types"])
        entry = {
            "tool_id": tool_id,
            "validator_id": definition.get("validator_id"),
            "name": base.get("name", tool_id),
            "description": base.get("description", definition["description"]),
            "category": base.get("category", "internal"),
            "available": True,
            "vulnerability_types": vuln_types,
            "vuln_types": list(base.get("vuln_types", vuln_types)),
            "requires_all": list(definition.get("requires_all", ())),
            "requires_any": list(definition.get("requires_any", ())),
            "provides": list(definition.get("provides", ())),
            "automatic_allowed": bool(
                definition.get("automatic_allowed", True)
            ),
            "allowed_options": list(definition.get("allowed_options", ())),
        }
        tools.append(_only(entry, _TOOL_FIELDS))
    for entry in technique_tool_catalog():
        tools.append(_only(entry, _TOOL_FIELDS))
    return tools


def _tool_index(tools: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {tool["tool_id"]: tool for tool in tools}


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def _scenario_t1190() -> List[Dict[str, Any]]:
    """Validator-first, then escalate; finish when the work is confirmed."""
    tools = default_available_tools()
    reachability = _finding(
        finding_id="finding-reachability",
        vulnerability_type="service_scan",
        severity="info",
        validation_status="confirmed",
        endpoint="/",
        mitre_technique_id=None,
        mitre_technique_name=None,
        mitre_tactic=None,
        validation_confidence=1.0,
        requires_any=["unauthenticated"],
        provides=["discovered_services"],
    )
    sqli = _finding(
        finding_id="finding-sqli",
        vulnerability_type="sql_injection",
        severity="critical",
        validation_status="detected",
        endpoint="/items",
        mitre_technique_id="T1190",
        mitre_technique_name=TECHNIQUE_NAMES["T1190"],
        mitre_tactic="Initial Access",
        validator_id="generic-http-sqli",
        http_method="GET",
        parameter_name="id",
        parameter_location="query",
        requires_any=["discovered_services", "reachable_web_application"],
        provides=["application_compromise", "possible_database_access"],
    )
    base_caps = ["unauthenticated", "discovered_services"]
    techniques = ["T1190"]
    options = {
        "endpoint": "/items",
        "http_method": "GET",
        "parameter_name": "id",
        "parameter_location": "query",
    }

    step0 = _state(
        findings=[reachability, sqli],
        capabilities=base_caps,
        mitre_techniques=techniques,
        current_step=0,
    )
    out0 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1190-1",
            tool_id="validate-sql-injection",
            finding_id="finding-sqli",
            reason="Run the registered deterministic validator before escalating.",
            expected_capabilities=["discovered_services"],
            options=options,
        ),
    }
    sup0 = _supervision(
        technique_id="T1190",
        output=out0,
        rejected=[
            _reject(
                tool_id="sqlmap-exploit",
                finding_id="finding-sqli",
                code="deferred_escalation",
                reason=(
                    "External exploitation is deferred until the registered "
                    "validator has produced its result."
                ),
                options=options,
            )
        ],
        notes=[
            "Validator first; escalate only after an inconclusive result.",
        ],
    )

    obs0 = _observation(
        action_id="action-t1190-1",
        tool_id="validate-sql-injection",
        finding_id="finding-sqli",
        validation_status="inconclusive",
        validation_decision="no_differential_reproduced",
        summary="The validator did not reproduce a differential response.",
        options_used=options,
        observed_http_status=200,
        observed_response_length=412,
    )
    step1 = _state(
        findings=[reachability, sqli],
        capabilities=base_caps,
        mitre_techniques=techniques,
        observations=[obs0],
        executed_action_ids=["action-t1190-1"],
        current_step=1,
    )
    out1 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1190-2",
            tool_id="sqlmap-exploit",
            finding_id="finding-sqli",
            reason="Escalate the inconclusive validator result to sqlmap.",
            expected_capabilities=["discovered_services"],
            options=options,
        ),
    }
    sup1 = _supervision(
        technique_id="T1190",
        output=out1,
        rejected=[
            _reject(
                tool_id="validate-sql-injection",
                finding_id="finding-sqli",
                code="denied_duplicate",
                reason="This exact validator action already ran.",
                options=options,
            ),
            _reject(
                tool_id="technique:T1059.004",
                finding_id="finding-sqli",
                code="denied_prerequisite",
                reason=(
                    "Unix shell execution requires application_compromise, "
                    "which has not been established."
                ),
            ),
        ],
        notes=[
            "The second attempt must change the tool, not repeat the validator.",
        ],
    )

    obs1 = _observation(
        action_id="action-t1190-2",
        tool_id="sqlmap-exploit",
        finding_id="finding-sqli",
        validation_status="confirmed",
        validation_decision="injection_confirmed",
        capabilities_gained=[
            "application_compromise",
            "possible_database_access",
        ],
        summary="sqlmap confirmed the injection and database access.",
        options_used=options,
        observed_http_status=200,
        observed_response_length=1280,
    )
    confirmed_sqli = dict(sqli)
    confirmed_sqli["validation_status"] = "confirmed"
    confirmed_sqli["validation_confidence"] = 0.95
    step2 = _state(
        findings=[reachability, confirmed_sqli],
        capabilities=[
            *base_caps,
            "application_compromise",
            "possible_database_access",
        ],
        mitre_techniques=techniques,
        observations=[obs0, obs1],
        executed_action_ids=["action-t1190-1", "action-t1190-2"],
        current_step=2,
    )
    out2 = _complete()
    sup2 = _supervision(
        technique_id="T1190",
        output=out2,
        rejected=[
            _reject(
                tool_id="sqlmap-exploit",
                finding_id="finding-sqli",
                code="denied_duplicate",
                reason="The exploit already succeeded; repeating it is a duplicate.",
                options=options,
            )
        ],
        notes=[
            "The finding is confirmed and no unvalidated work remains; complete.",
        ],
    )

    return [
        _record(
            scenario_id="t1190-validator-then-escalation",
            state=step0,
            tools=tools,
            output=out0,
            supervision=sup0,
        ),
        _record(
            scenario_id="t1190-validator-then-escalation",
            state=step1,
            tools=tools,
            output=out1,
            supervision=sup1,
        ),
        _record(
            scenario_id="t1190-validator-then-escalation",
            state=step2,
            tools=tools,
            output=out2,
            supervision=sup2,
        ),
    ]


def _scenario_t1059_t1082() -> List[Dict[str, Any]]:
    """Shell execution needs compromise; discovery needs command execution."""
    tools = default_available_tools()
    sqli = _finding(
        finding_id="finding-sqli",
        vulnerability_type="sql_injection",
        severity="critical",
        validation_status="confirmed",
        endpoint="/items",
        mitre_technique_id="T1190",
        mitre_technique_name=TECHNIQUE_NAMES["T1190"],
        mitre_tactic="Initial Access",
        validator_id="generic-http-sqli",
        validation_confidence=0.96,
        requires_any=["discovered_services"],
        provides=["application_compromise", "possible_database_access"],
    )
    rce = _finding(
        finding_id="finding-rce",
        vulnerability_type="rce",
        severity="critical",
        validation_status="detected",
        endpoint="/diagnostics",
        mitre_technique_id="T1059.004",
        mitre_technique_name=TECHNIQUE_NAMES["T1059.004"],
        mitre_tactic="Execution",
        validator_id="generic-http-command-execution",
        http_method="POST",
        parameter_name="cmd",
        parameter_location="form",
        requires_any=["application_compromise"],
        provides=["command_execution"],
    )
    base_caps = [
        "unauthenticated",
        "discovered_services",
        "application_compromise",
        "possible_database_access",
    ]
    techniques = ["T1190", "T1059.004", "T1082"]
    options = {"endpoint": "/diagnostics", "parameter_name": "cmd"}

    step0 = _state(
        findings=[sqli, rce],
        capabilities=base_caps,
        mitre_techniques=techniques,
        current_step=0,
    )
    out0 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1059-1",
            tool_id="technique:T1059.004",
            finding_id="finding-rce",
            reason=(
                "Application compromise is established; obtain Unix shell "
                "command execution through the RCE finding."
            ),
            expected_capabilities=["application_compromise"],
            options=options,
        ),
    }
    sup0 = _supervision(
        technique_id="T1059.004",
        output=out0,
        rejected=[
            _reject(
                tool_id="technique:T1082",
                finding_id="finding-rce",
                code="denied_prerequisite",
                reason=(
                    "System information discovery requires command_execution, "
                    "which is not yet held."
                ),
            ),
            _reject(
                tool_id="technique:T1548",
                finding_id="finding-rce",
                code="denied_prerequisite",
                reason=(
                    "Elevation-control enumeration also requires "
                    "command_execution first."
                ),
            ),
        ],
        notes=[
            "The shell capability is gated on application_compromise, not on "
            "the mere existence of an RCE finding.",
        ],
    )

    obs0 = _observation(
        action_id="action-t1059-1",
        tool_id="technique:T1059.004",
        finding_id="finding-rce",
        validation_status="confirmed",
        validation_decision="marker_executed_on_target",
        capabilities_gained=["command_execution"],
        summary="A fixed marker command executed on the target.",
        options_used=options,
        observed_http_status=200,
        observed_response_length=96,
    )
    step1 = _state(
        findings=[sqli, rce],
        capabilities=[*base_caps, "command_execution"],
        mitre_techniques=techniques,
        observations=[obs0],
        executed_action_ids=["action-t1059-1"],
        current_step=1,
    )
    out1 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1082-1",
            tool_id="technique:T1082",
            finding_id="finding-rce",
            reason=(
                "Command execution is established; enumerate target system "
                "information."
            ),
            expected_capabilities=["command_execution"],
            options=options,
        ),
    }
    sup1 = _supervision(
        technique_id="T1082",
        output=out1,
        rejected=[
            _reject(
                tool_id="technique:T1059.004",
                finding_id="finding-rce",
                code="denied_duplicate",
                reason="The shell-execution action already ran.",
                options=options,
            )
        ],
        notes=["Discovery follows command execution; it never precedes it."],
    )

    obs1 = _observation(
        action_id="action-t1082-1",
        tool_id="technique:T1082",
        finding_id="finding-rce",
        validation_status="confirmed",
        capabilities_gained=["system_information"],
        summary="Operating-system and hardware information was read on target.",
        options_used=options,
        observed_http_status=200,
        observed_response_length=220,
    )
    step2 = _state(
        findings=[sqli, rce],
        capabilities=[*base_caps, "command_execution", "system_information"],
        mitre_techniques=techniques,
        observations=[obs0, obs1],
        executed_action_ids=["action-t1059-1", "action-t1082-1"],
        current_step=2,
    )
    out2 = _complete()
    sup2 = _supervision(
        technique_id="T1082",
        output=out2,
        rejected=[
            _reject(
                tool_id="technique:T1082",
                finding_id="finding-rce",
                code="denied_duplicate",
                reason="Discovery already ran against this finding.",
                options=options,
            )
        ],
        notes=["No further capability is required; complete."],
    )

    return [
        _record(
            scenario_id="t1059-t1082-capability-chain",
            state=step0,
            tools=tools,
            output=out0,
            supervision=sup0,
        ),
        _record(
            scenario_id="t1059-t1082-capability-chain",
            state=step1,
            tools=tools,
            output=out1,
            supervision=sup1,
        ),
        _record(
            scenario_id="t1059-t1082-capability-chain",
            state=step2,
            tools=tools,
            output=out2,
            supervision=sup2,
        ),
    ]


def _scenario_t1078_t1213() -> List[Dict[str, Any]]:
    """Credentials are not a session; collection needs the session."""
    tools = default_available_tools()
    reachability = _finding(
        finding_id="finding-reachability",
        vulnerability_type="service_scan",
        severity="info",
        validation_status="confirmed",
        endpoint="/",
        mitre_technique_id=None,
        mitre_technique_name=None,
        mitre_tactic=None,
        validation_confidence=1.0,
        requires_any=["unauthenticated"],
        provides=["discovered_services"],
    )
    credentials = _finding(
        finding_id="finding-credentials",
        vulnerability_type="default_credentials",
        severity="high",
        validation_status="detected",
        endpoint="/login",
        mitre_technique_id="T1078",
        mitre_technique_name=TECHNIQUE_NAMES["T1078"],
        mitre_tactic="Initial Access",
        http_method="POST",
        parameter_name="username",
        parameter_location="form",
        requires_any=["discovered_services", "reachable_login_service"],
        provides=["credential_access"],
    )
    repo = _finding(
        finding_id="finding-repository",
        vulnerability_type="database_repository_access",
        severity="high",
        validation_status="detected",
        endpoint="/admin/console",
        mitre_technique_id="T1213",
        mitre_technique_name=TECHNIQUE_NAMES["T1213"],
        mitre_tactic="Collection",
        requires_any=["authenticated_session"],
        provides=["repository_data_access"],
    )
    base_caps = ["unauthenticated", "discovered_services"]
    techniques = ["T1078", "T1213"]
    login_options = {
        "endpoint": "/login",
        "http_method": "POST",
        "parameter_name": "username",
        "parameter_location": "form",
    }

    step0 = _state(
        findings=[reachability, credentials, repo],
        capabilities=base_caps,
        mitre_techniques=techniques,
        current_step=0,
    )
    out0 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1078-1",
            tool_id="hydra-brute",
            finding_id="finding-credentials",
            reason="Test the exposed login surface for accepted credentials.",
            expected_capabilities=["discovered_services"],
            options=login_options,
        ),
    }
    sup0 = _supervision(
        technique_id="T1078",
        output=out0,
        rejected=[
            _reject(
                tool_id="technique:T1213",
                finding_id="finding-credentials",
                code="denied_prerequisite",
                reason=(
                    "Repository collection requires application_compromise, "
                    "possible_database_access, or authenticated_session."
                ),
            )
        ],
        notes=[
            "Accepted credentials grant credential_access only, not a session.",
        ],
    )

    obs0 = _observation(
        action_id="action-t1078-1",
        tool_id="hydra-brute",
        finding_id="finding-credentials",
        validation_status="confirmed",
        validation_decision="credentials_accepted",
        capabilities_gained=["credential_access"],
        summary="A valid credential pair was accepted; no session was opened.",
        options_used=login_options,
        observed_http_status=302,
        observed_response_length=0,
    )
    creds_confirmed = dict(credentials)
    creds_confirmed["validation_status"] = "confirmed"
    creds_confirmed["validation_confidence"] = 0.9
    step1 = _state(
        findings=[reachability, creds_confirmed, repo],
        capabilities=[*base_caps, "credential_access"],
        mitre_techniques=techniques,
        observations=[obs0],
        executed_action_ids=["action-t1078-1"],
        current_step=1,
    )
    session_options = {"endpoint": "/admin/console"}
    out1 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1078-2",
            tool_id="technique:T1078",
            finding_id="finding-credentials",
            reason=(
                "Use the accepted credentials to establish an authenticated "
                "session."
            ),
            expected_capabilities=["credential_access", "discovered_services"],
            options=session_options,
        ),
    }
    sup1 = _supervision(
        technique_id="T1078",
        output=out1,
        rejected=[
            _reject(
                tool_id="technique:T1213",
                finding_id="finding-credentials",
                code="denied_prerequisite",
                reason=(
                    "credential_access alone is not authenticated_session; "
                    "collection stays denied until a session exists."
                ),
            ),
            _reject(
                tool_id="hydra-brute",
                finding_id="finding-credentials",
                code="denied_duplicate",
                reason="The same credential test already ran with these options.",
                options=login_options,
            ),
        ],
        notes=[
            "Only the T1078 session step may add authenticated_session.",
        ],
    )

    obs1 = _observation(
        action_id="action-t1078-2",
        tool_id="technique:T1078",
        finding_id="finding-credentials",
        validation_status="confirmed",
        validation_decision="session_established",
        capabilities_gained=["authenticated_session"],
        summary="A live authenticated session was established with the credentials.",
        options_used=session_options,
        observed_http_status=200,
        observed_response_length=640,
    )
    step2 = _state(
        findings=[reachability, creds_confirmed, repo],
        capabilities=[
            *base_caps,
            "credential_access",
            "authenticated_session",
        ],
        mitre_techniques=techniques,
        observations=[obs0, obs1],
        executed_action_ids=["action-t1078-1", "action-t1078-2"],
        current_step=2,
    )
    out2 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1213-1",
            tool_id="technique:T1213",
            finding_id="finding-repository",
            reason=(
                "An authenticated session exists; collect data from the "
                "information repository."
            ),
            expected_capabilities=["authenticated_session"],
            options=session_options,
        ),
    }
    sup2 = _supervision(
        technique_id="T1213",
        output=out2,
        rejected=[
            _reject(
                tool_id="technique:T1078",
                finding_id="finding-credentials",
                code="denied_duplicate",
                reason="The session-establishment action already ran.",
                options=session_options,
            )
        ],
        notes=["Collection is unlocked by authenticated_session, not by credentials."],
    )

    obs2 = _observation(
        action_id="action-t1213-1",
        tool_id="technique:T1213",
        finding_id="finding-repository",
        validation_status="confirmed",
        capabilities_gained=["repository_data_access"],
        summary="Repository data was read through the authenticated session.",
        options_used=session_options,
        observed_http_status=200,
        observed_response_length=2048,
    )
    step3 = _state(
        findings=[reachability, creds_confirmed, repo],
        capabilities=[
            *base_caps,
            "credential_access",
            "authenticated_session",
            "repository_data_access",
        ],
        mitre_techniques=techniques,
        observations=[obs0, obs1, obs2],
        executed_action_ids=[
            "action-t1078-1",
            "action-t1078-2",
            "action-t1213-1",
        ],
        current_step=3,
    )
    out3 = _complete()
    sup3 = _supervision(
        technique_id="T1213",
        output=out3,
        rejected=[
            _reject(
                tool_id="technique:T1213",
                finding_id="finding-repository",
                code="denied_duplicate",
                reason="Repository collection already ran.",
                options=session_options,
            )
        ],
        notes=["Collection is confirmed; complete."],
    )

    return [
        _record(
            scenario_id="t1078-t1213-credential-session-split",
            state=step0,
            tools=tools,
            output=out0,
            supervision=sup0,
        ),
        _record(
            scenario_id="t1078-t1213-credential-session-split",
            state=step1,
            tools=tools,
            output=out1,
            supervision=sup1,
        ),
        _record(
            scenario_id="t1078-t1213-credential-session-split",
            state=step2,
            tools=tools,
            output=out2,
            supervision=sup2,
        ),
        _record(
            scenario_id="t1078-t1213-credential-session-split",
            state=step3,
            tools=tools,
            output=out3,
            supervision=sup3,
        ),
    ]


def _scenario_t1548_t1068() -> List[Dict[str, Any]]:
    """Enumerate elevation vectors, then escalate; root needs uid=0."""
    tools = default_available_tools()
    rce = _finding(
        finding_id="finding-rce",
        vulnerability_type="rce",
        severity="critical",
        validation_status="confirmed",
        endpoint="/diagnostics",
        mitre_technique_id="T1059.004",
        mitre_technique_name=TECHNIQUE_NAMES["T1059.004"],
        mitre_tactic="Execution",
        validator_id="generic-http-command-execution",
        http_method="POST",
        parameter_name="cmd",
        parameter_location="form",
        validation_confidence=0.95,
        requires_any=["application_compromise"],
        provides=["command_execution"],
    )
    base_caps = [
        "unauthenticated",
        "discovered_services",
        "application_compromise",
        "command_execution",
    ]
    techniques = ["T1059.004", "T1548", "T1068"]
    options = {"endpoint": "/diagnostics", "parameter_name": "cmd"}
    misconfig = _finding(
        finding_id="finding-misconfiguration",
        vulnerability_type="misconfiguration",
        severity="high",
        validation_status="detected",
        endpoint="/diagnostics",
        mitre_technique_id="T1548",
        mitre_technique_name=TECHNIQUE_NAMES["T1548"],
        mitre_tactic="Privilege Escalation",
        validator_id="generic-http-misconfiguration",
        http_method="POST",
        parameter_name="cmd",
        parameter_location="form",
        requires_any=["command_execution"],
        provides=["local_privilege_escalation"],
    )

    step0 = _state(
        findings=[rce, misconfig],
        capabilities=base_caps,
        mitre_techniques=techniques,
        current_step=0,
    )
    out0 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1548-1",
            tool_id="technique:T1548",
            finding_id="finding-misconfiguration",
            reason=(
                "Enumerate elevation-control vectors before attempting "
                "privilege-escalation exploitation."
            ),
            expected_capabilities=["command_execution"],
            options=options,
        ),
    }
    sup0 = _supervision(
        technique_id="T1548",
        output=out0,
        rejected=[
            _reject(
                tool_id="technique:T1068",
                finding_id="finding-misconfiguration",
                code="deferred_escalation",
                reason=(
                    "Exploit a specific elevation vector after enumeration, "
                    "not before it."
                ),
                options=options,
            )
        ],
        notes=["T1548 enumerates; T1068 exploits a confirmed vector."],
    )

    obs0 = _observation(
        action_id="action-t1548-1",
        tool_id="technique:T1548",
        finding_id="finding-misconfiguration",
        validation_status="confirmed",
        capabilities_gained=["local_privilege_escalation"],
        summary="A concrete SUID/sudo elevation vector was enumerated on target.",
        options_used=options,
        observed_http_status=200,
        observed_response_length=512,
    )
    step1 = _state(
        findings=[rce, misconfig],
        capabilities=[*base_caps, "local_privilege_escalation"],
        mitre_techniques=techniques,
        observations=[obs0],
        executed_action_ids=["action-t1548-1"],
        current_step=1,
    )
    out1 = {
        "decision": "action",
        "action": _action(
            action_id="action-t1068-1",
            tool_id="technique:T1068",
            finding_id="finding-misconfiguration",
            reason=(
                "Exploit the enumerated elevation vector to attempt root "
                "access."
            ),
            expected_capabilities=["local_privilege_escalation"],
            options=options,
        ),
    }
    sup1 = _supervision(
        technique_id="T1068",
        output=out1,
        rejected=[
            _reject(
                tool_id="technique:T1548",
                finding_id="finding-misconfiguration",
                code="denied_duplicate",
                reason="Elevation enumeration already ran.",
                options=options,
            )
        ],
        notes=["Escalation follows enumeration."],
    )

    obs1 = _observation(
        action_id="action-t1068-1",
        tool_id="technique:T1068",
        finding_id="finding-misconfiguration",
        validation_status="inconclusive",
        validation_decision="no_uid0_evidence",
        capabilities_gained=[],
        summary=(
            "Privilege-escalation enumeration ran, but no uid=0 evidence "
            "was observed; root access is not claimed."
        ),
        options_used=options,
        observed_http_status=200,
        observed_response_length=4096,
    )
    step2 = _state(
        findings=[rce, misconfig],
        capabilities=[*base_caps, "local_privilege_escalation"],
        mitre_techniques=techniques,
        observations=[obs0, obs1],
        executed_action_ids=["action-t1548-1", "action-t1068-1"],
        current_step=2,
    )
    out2 = _complete()
    sup2 = _supervision(
        technique_id="T1068",
        output=out2,
        rejected=[
            _reject(
                tool_id="technique:T1068",
                finding_id="finding-misconfiguration",
                code="denied_duplicate",
                reason="The escalation attempt already ran.",
                options=options,
            ),
            _reject(
                tool_id="technique:T1068",
                finding_id="finding-misconfiguration",
                code="root_claim_without_uid0",
                reason=(
                    "root_access may only be claimed from real uid=0 output; "
                    "enumeration output is not root evidence."
                ),
                options=options,
            ),
        ],
        notes=[
            "No uid=0 evidence: local_privilege_escalation is held, root_access "
            "is not.",
        ],
    )

    return [
        _record(
            scenario_id="t1548-t1068-privilege-honesty",
            state=step0,
            tools=tools,
            output=out0,
            supervision=sup0,
        ),
        _record(
            scenario_id="t1548-t1068-privilege-honesty",
            state=step1,
            tools=tools,
            output=out1,
            supervision=sup1,
        ),
        _record(
            scenario_id="t1548-t1068-privilege-honesty",
            state=step2,
            tools=tools,
            output=out2,
            supervision=sup2,
        ),
    ]


def _scenario_t1595() -> List[Dict[str, Any]]:
    """T1595 is observed adversary scanning, never Obsidian's own scans."""
    tools = default_available_tools()
    observed = _finding(
        finding_id="finding-observed-scan",
        vulnerability_type="observed_adversary_active_scanning",
        severity="medium",
        validation_status="confirmed",
        endpoint="/",
        mitre_technique_id="T1595",
        mitre_technique_name=TECHNIQUE_NAMES["T1595"],
        mitre_tactic="Reconnaissance",
        validation_confidence=0.9,
        requires_any=["unauthenticated"],
        provides=["adversary_reconnaissance_observed"],
    )
    own_scan = _finding(
        finding_id="finding-own-scan",
        vulnerability_type="service_scan",
        severity="info",
        validation_status="confirmed",
        endpoint="/",
        mitre_technique_id=None,
        mitre_technique_name=None,
        mitre_tactic=None,
        validation_confidence=1.0,
        requires_any=["unauthenticated"],
        provides=["discovered_services"],
    )
    state = _state(
        findings=[own_scan, observed],
        capabilities=[
            "unauthenticated",
            "discovered_services",
            "adversary_reconnaissance_observed",
        ],
        mitre_techniques=["T1595"],
        current_step=0,
    )
    output = _complete()
    supervision = _supervision(
        technique_id="T1595",
        output=output,
        rejected=[
            _reject(
                tool_id="technique:T1595",
                finding_id="finding-own-scan",
                code="not_adversary_action",
                reason=(
                    "Obsidian's own service scan is an environmental fact, not "
                    "adversary T1595 behavior. T1595 records observed adversary "
                    "scanning only."
                ),
            )
        ],
        notes=[
            "The observed-scan finding is already confirmed and informational; "
            "no follow-up technique action is warranted.",
        ],
    )
    return [
        _record(
            scenario_id="t1595-observed-adversary-scan",
            state=state,
            tools=tools,
            output=output,
            supervision=supervision,
        )
    ]


def _scenario_guardrails() -> List[Dict[str, Any]]:
    """Fail-closed negatives at the step budget."""
    tools = default_available_tools()
    sqli = _finding(
        finding_id="finding-sqli",
        vulnerability_type="sql_injection",
        severity="critical",
        validation_status="detected",
        endpoint="/items",
        mitre_technique_id="T1190",
        mitre_technique_name=TECHNIQUE_NAMES["T1190"],
        mitre_tactic="Initial Access",
        validator_id="generic-http-sqli",
        validation_confidence=0.2,
        requires_any=["discovered_services"],
        provides=["application_compromise", "possible_database_access"],
    )
    state = _state(
        findings=[sqli],
        capabilities=["unauthenticated", "discovered_services"],
        mitre_techniques=["T1190"],
        current_step=1,
        maximum_steps=1,
        observations=[
            _observation(
                action_id="action-g-1",
                tool_id="validate-sql-injection",
                finding_id="finding-sqli",
                validation_status="inconclusive",
                summary="The validator did not confirm the candidate.",
                options_used={"endpoint": "/items"},
                observed_http_status=200,
                observed_response_length=400,
            )
        ],
        executed_action_ids=["action-g-1"],
    )
    output = _complete()
    options = {"endpoint": "/items"}
    step0_state = _state(
        findings=[sqli],
        capabilities=["unauthenticated", "discovered_services"],
        mitre_techniques=["T1190"],
        current_step=0,
        maximum_steps=1,
    )
    step0_output = {
        "decision": "action",
        "action": _action(
            action_id="action-g-1",
            tool_id="validate-sql-injection",
            finding_id="finding-sqli",
            reason="Run the registered validator on the remaining finding.",
            expected_capabilities=["discovered_services"],
            options=options,
        ),
    }
    step0_supervision = _supervision(
        technique_id="T1190",
        output=step0_output,
        notes=["One step remains in the budget."],
    )
    supervision = _supervision(
        technique_id="T1190",
        output=output,
        rejected=[
            _reject(
                tool_id="validate-sql-injection",
                finding_id="finding-sqli",
                code="denied_step_limit",
                reason="The configured step budget is exhausted.",
                options=options,
            ),
            _reject(
                tool_id="shell-exec",
                finding_id="finding-sqli",
                code="denied_unknown_tool",
                reason="The tool is not registered; fail closed.",
            ),
            _reject(
                tool_id="validate-sql-injection",
                finding_id="finding-sqli",
                code="denied_invalid_reference",
                reason="The planner changed the trusted scan identifier.",
                options=options,
                scan_id="scan-other",
            ),
        ],
        notes=[
            "At the step limit the only valid decision is complete.",
            "Unknown tools and changed identifiers are rejected, never repaired.",
        ],
    )
    return [
        _record(
            scenario_id="guardrails-step-limit-fail-closed",
            state=step0_state,
            tools=tools,
            output=step0_output,
            supervision=step0_supervision,
        ),
        _record(
            scenario_id="guardrails-step-limit-fail-closed",
            state=state,
            tools=tools,
            output=output,
            supervision=supervision,
        ),
    ]


def build_dataset() -> List[Dict[str, Any]]:
    """Return the full deterministic dataset, ordered by scenario and step."""
    records: List[Dict[str, Any]] = []
    for builder in (
        _scenario_t1595,
        _scenario_t1190,
        _scenario_t1059_t1082,
        _scenario_t1078_t1213,
        _scenario_t1548_t1068,
        _scenario_guardrails,
    ):
        records.extend(builder())
    return records


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _same_origin(endpoint: str, target: str) -> bool:
    endpoint = str(endpoint or "")
    parsed_endpoint = urlparse(endpoint)
    if not parsed_endpoint.scheme and not parsed_endpoint.netloc:
        # Relative paths inherit the trusted target origin.
        return not endpoint.startswith("\\\\")
    parsed_target = urlparse(target)
    if not parsed_endpoint.scheme or not parsed_endpoint.hostname:
        return False
    return (
        parsed_endpoint.scheme == parsed_target.scheme
        and parsed_endpoint.hostname == parsed_target.hostname
        and (parsed_endpoint.port or _default_port(parsed_endpoint.scheme))
        == (parsed_target.port or _default_port(parsed_target.scheme))
    )


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _walk(value: Any) -> Iterable[Tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key), child
            yield from _walk(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk(child)


def _forbidden_content(value: Any) -> List[str]:
    problems: List[str] = []
    for key, child in _walk(value):
        if key.lower() in FORBIDDEN_KEYS:
            problems.append(f"forbidden key {key!r}")
        if isinstance(child, str):
            for pattern in FORBIDDEN_VALUE_PATTERNS:
                if pattern.search(child):
                    problems.append(
                        f"forbidden value pattern {pattern.pattern!r} under {key!r}"
                    )
    return problems


def _action_fingerprint(action: Mapping[str, Any]) -> Tuple[Any, ...]:
    options = action.get("options") or {}
    return (
        action.get("tool_id"),
        action.get("finding_id"),
        tuple(sorted(options.items())),
    )


def _observation_fingerprints(
    observations: Sequence[Mapping[str, Any]],
) -> set:
    fingerprints = set()
    for observation in observations:
        if not observation.get("policy_allowed"):
            continue
        if observation.get("finding_id") is None:
            continue
        options = observation.get("options_used") or []
        fingerprints.add(
            (
                observation.get("tool_id"),
                observation.get("finding_id"),
                tuple(sorted(tuple(item) for item in options)),
            )
        )
    return fingerprints


def validate_record(record: Mapping[str, Any]) -> List[str]:
    """Return every contract violation in one record (empty means valid)."""
    errors: List[str] = []
    if not isinstance(record, Mapping):
        return ["record must be an object"]
    if set(record) != TOP_LEVEL_FIELDS:
        errors.append(
            "top-level fields must be exactly "
            f"{sorted(TOP_LEVEL_FIELDS)}, got {sorted(record)}"
        )
    scenario_id = record.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        errors.append("scenario_id must be a non-empty string")
    step_index = record.get("step_index")
    if isinstance(step_index, bool) or not isinstance(step_index, int):
        errors.append("step_index must be an integer")

    state = record.get("state")
    tools = record.get("available_tools")
    output = record.get("output")
    supervision = record.get("supervision")
    if not isinstance(state, Mapping):
        errors.append("state must be an object")
        return errors
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        errors.append("available_tools must be a list")
        return errors
    if not isinstance(output, Mapping):
        errors.append("output must be an object")
        return errors
    if not isinstance(supervision, Mapping):
        errors.append("supervision must be an object")
        return errors

    errors.extend(_forbidden_content(state))
    errors.extend(_forbidden_content(tools))
    errors.extend(_forbidden_content(output))

    expected_state_keys = set(_STATE_FIELDS) | {"findings", "observations"}
    if set(state) != expected_state_keys:
        errors.append(
            "state fields must be exactly the planner state contract: "
            f"missing={sorted(expected_state_keys - set(state))}, "
            f"extra={sorted(set(state) - expected_state_keys)}"
        )
    findings = state.get("findings")
    observations = state.get("observations")
    if not isinstance(findings, list):
        errors.append("state.findings must be a list")
        findings = []
    if not isinstance(observations, list):
        errors.append("state.observations must be a list")
        observations = []

    if state.get("scan_id") != SCAN_ID:
        errors.append("state.scan_id must match the dataset scan")
    if state.get("asset_id") != ASSET_ID:
        errors.append("state.asset_id must match the dataset asset")
    if state.get("target") != TARGET:
        errors.append("state.target must match the dataset target")
    if state.get("authorized") is not True:
        errors.append("state.authorized must be true")
    if state.get("scan_exists") is not True:
        errors.append("state.scan_exists must be true")
    if state.get("status") != "running":
        errors.append("state.status must be 'running'")
    if step_index != state.get("current_step"):
        errors.append("step_index must equal state.current_step")
    current_step = state.get("current_step")
    maximum_steps = state.get("maximum_steps")
    if not isinstance(maximum_steps, int) or maximum_steps < 1:
        errors.append("state.maximum_steps must be a positive integer")
    if (
        isinstance(current_step, int)
        and isinstance(maximum_steps, int)
        and current_step > maximum_steps
    ):
        errors.append("state.current_step cannot exceed maximum_steps")

    findings_by_id: Dict[str, Mapping[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, Mapping):
            errors.append("every finding must be an object")
            continue
        extra = set(finding) - set(_FINDING_FIELDS)
        if extra:
            errors.append(f"finding has non-planner fields: {sorted(extra)}")
        missing = {
            "finding_id",
            "scan_id",
            "asset_id",
            "target",
            "vulnerability_type",
            "validation_status",
        } - set(finding)
        if missing:
            errors.append(f"finding is missing fields: {sorted(missing)}")
        finding_id = finding.get("finding_id")
        if finding_id in findings_by_id:
            errors.append(f"duplicate finding_id {finding_id!r}")
        findings_by_id[finding_id] = finding
        if finding.get("scan_id") != SCAN_ID:
            errors.append(f"finding {finding_id!r} scan_id mismatch")
        if finding.get("asset_id") != ASSET_ID:
            errors.append(f"finding {finding_id!r} asset_id mismatch")
        if finding.get("target") != TARGET:
            errors.append(f"finding {finding_id!r} target mismatch")
        if finding.get("mitre_technique_id") not in (None, *TECHNIQUE_IDS):
            errors.append(
                f"finding {finding_id!r} uses a non-dataset technique"
            )

    validation_states = state.get("validation_states")
    expected_validation_states = {
        finding_id: finding.get("validation_status")
        for finding_id, finding in findings_by_id.items()
    }
    if validation_states != expected_validation_states:
        errors.append(
            "state.validation_states must mirror the finding validation states"
        )

    for observation in observations:
        if not isinstance(observation, Mapping):
            errors.append("every observation must be an object")
            continue
        extra = set(observation) - set(_OBSERVATION_FIELDS)
        if extra:
            errors.append(f"observation has non-planner fields: {sorted(extra)}")
        if observation.get("finding_id") not in findings_by_id:
            errors.append("observation references an unknown finding")
        if observation.get("policy_allowed") is not True:
            errors.append("training observations must be allowed")
        for key, value in (observation.get("options_used") or []):
            if key not in ALLOWED_OPTION_KEYS:
                errors.append(f"observation uses unsupported option {key!r}")
            if key == "endpoint" and not _same_origin(value, TARGET):
                errors.append("observation endpoint is outside the origin")

    tool_index: Dict[str, Mapping[str, Any]] = {}
    for tool in tools:
        if not isinstance(tool, Mapping):
            errors.append("every tool must be an object")
            continue
        extra = set(tool) - set(_TOOL_FIELDS)
        if extra:
            errors.append(f"tool has non-planner fields: {sorted(extra)}")
        tool_id = tool.get("tool_id")
        if not isinstance(tool_id, str) or not tool_id:
            errors.append("tool_id must be a non-empty string")
            continue
        if tool_id in tool_index:
            errors.append(f"duplicate tool_id {tool_id!r}")
        tool_index[tool_id] = tool
        if tool.get("available") is not True:
            errors.append(f"tool {tool_id!r} must be available")
        allowed = tool.get("allowed_options") or []
        if not set(allowed) <= ALLOWED_OPTION_KEYS:
            errors.append(f"tool {tool_id!r} advertises unsupported options")
        if tool_id.startswith("technique:"):
            technique_id = tool_id.split(":", 1)[1]
            if technique_id not in TECHNIQUE_IDS:
                errors.append(
                    f"technique tool {tool_id!r} is outside the 8 techniques"
                )

    if set(output) != {"decision", "action"}:
        errors.append("output fields must be exactly decision and action")
    decision = output.get("decision")
    action = output.get("action")
    if decision == "complete":
        if action is not None:
            errors.append("complete output must carry action=null")
    elif decision == "action":
        if not isinstance(action, Mapping):
            errors.append("action output must carry an action object")
        else:
            extra = set(action) - ACTION_FIELDS
            if extra:
                errors.append(f"action has unsupported fields: {sorted(extra)}")
            missing = ACTION_FIELDS - set(action)
            if missing:
                errors.append(f"action is missing fields: {sorted(missing)}")
            if action.get("scan_id") != state.get("scan_id"):
                errors.append("action changed state.scan_id")
            if action.get("asset_id") != state.get("asset_id"):
                errors.append("action changed state.asset_id")
            if action.get("target") != state.get("target"):
                errors.append("action changed state.target")
            finding_id = action.get("finding_id")
            if finding_id not in findings_by_id:
                errors.append("action references an unknown finding")
            action_id = action.get("action_id")
            if action_id in (state.get("executed_action_ids") or []):
                errors.append("action_id is already in executed_action_ids")
            if _action_fingerprint(action) in _observation_fingerprints(
                observations
            ):
                errors.append("action repeats an executed tool/finding/options")
            if (
                isinstance(current_step, int)
                and isinstance(maximum_steps, int)
                and current_step >= maximum_steps
            ):
                errors.append("action exceeds the step budget")

            tool = tool_index.get(action.get("tool_id"))
            if tool is None:
                errors.append("action selected a tool not in available_tools")
            else:
                finding = findings_by_id.get(finding_id)
                vuln_types = {
                    normalize_vulnerability_type(value)
                    for value in (tool.get("vulnerability_types") or [])
                }
                if (
                    isinstance(finding, Mapping)
                    and vuln_types
                    and normalize_vulnerability_type(
                        finding.get("vulnerability_type", "")
                    )
                    not in vuln_types
                ):
                    errors.append(
                        f"tool {tool.get('tool_id')!r} is not compatible with "
                        "the selected finding's vulnerability type"
                    )
                allowed = set(tool.get("allowed_options") or [])
                options = action.get("options") or {}
                if not isinstance(options, Mapping):
                    errors.append("action.options must be an object")
                    options = {}
                for key, value in options.items():
                    if key not in ALLOWED_OPTION_KEYS:
                        errors.append(
                            f"action uses unsupported option {key!r}"
                        )
                    if key not in allowed:
                        errors.append(
                            f"tool {tool.get('tool_id')!r} does not advertise "
                            f"option {key!r}"
                        )
                    if key == "endpoint" and not _same_origin(value, TARGET):
                        errors.append(
                            "action endpoint is outside the trusted origin"
                        )
                capabilities = set(state.get("capabilities") or [])
                expected = set(action.get("expected_capabilities") or [])
                if not expected <= capabilities:
                    errors.append(
                        "action expects capabilities that are not held"
                    )
                requires_all = set(tool.get("requires_all") or [])
                if not requires_all <= capabilities:
                    errors.append(
                        f"tool {tool.get('tool_id')!r} prerequisites are unmet"
                    )
                requires_any = set(tool.get("requires_any") or [])
                if requires_any and not (requires_any & capabilities):
                    errors.append(
                        f"tool {tool.get('tool_id')!r} alternative "
                        "prerequisites are unmet"
                    )
    else:
        errors.append("decision must be 'action' or 'complete'")

    if set(supervision) != SUPERVISION_FIELDS:
        errors.append(
            "supervision fields must be exactly "
            f"{sorted(SUPERVISION_FIELDS)}"
        )
    if supervision.get("technique_id") not in TECHNIQUE_IDS:
        errors.append("supervision.technique_id must be one of the 8 techniques")
    if supervision.get("policy_outcome") not in {"allowed", "complete"}:
        errors.append("supervision.policy_outcome is invalid")
    rejected = supervision.get("rejected_candidates")
    if not isinstance(rejected, list):
        errors.append("supervision.rejected_candidates must be a list")
        rejected = []
    for rejected_item in rejected:
        if not isinstance(rejected_item, Mapping):
            errors.append("rejected candidate must be an object")
            continue
        if not isinstance(rejected_item.get("candidate"), Mapping):
            errors.append("rejected candidate is missing candidate metadata")
        if not isinstance(rejected_item.get("code"), str):
            errors.append("rejected candidate is missing a policy code")
        if not isinstance(rejected_item.get("reason"), str):
            errors.append("rejected candidate is missing a reason")
    return errors


def validate_dataset(records: Sequence[Mapping[str, Any]]) -> List[str]:
    """Validate every record plus dataset-level coverage and continuity."""
    errors: List[str] = []
    scenario_steps: Dict[str, List[int]] = {}
    techniques = set()
    negative_codes = set()
    for index, record in enumerate(records):
        for problem in validate_record(record):
            errors.append(f"record {index}: {problem}")
        if not isinstance(record, Mapping):
            continue
        scenario_id = record.get("scenario_id")
        step_index = record.get("step_index")
        scenario_steps.setdefault(str(scenario_id), []).append(step_index)
        supervision = record.get("supervision")
        if isinstance(supervision, Mapping):
            techniques.add(supervision.get("technique_id"))
            for rejected in supervision.get("rejected_candidates") or []:
                if isinstance(rejected, Mapping):
                    negative_codes.add(rejected.get("code"))

    for scenario_id, steps in scenario_steps.items():
        expected = list(range(len(steps)))
        if steps != expected:
            errors.append(
                f"scenario {scenario_id!r} steps must be contiguous from 0: "
                f"got {steps}"
            )

    missing_techniques = set(TECHNIQUE_IDS) - techniques
    if missing_techniques:
        errors.append(
            "dataset does not cover techniques: "
            f"{sorted(missing_techniques)}"
        )
    missing_negatives = REQUIRED_NEGATIVE_CODES - negative_codes
    if missing_negatives:
        errors.append(
            "dataset does not teach negative cases: "
            f"{sorted(missing_negatives)}"
        )
    return errors


def dumps_jsonl(records: Sequence[Mapping[str, Any]]) -> str:
    """Serialize records as canonical JSONL."""
    return "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    )


def validate_jsonl(text: str) -> List[str]:
    """Parse and validate a JSONL payload."""
    records = []
    errors: List[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: invalid JSON: {exc}")
            continue
        records.append(record)
    errors.extend(validate_dataset(records))
    return errors


__all__ = [
    "DatasetValidationError",
    "TECHNIQUE_IDS",
    "TECHNIQUE_NAMES",
    "build_dataset",
    "default_available_tools",
    "dumps_jsonl",
    "validate_dataset",
    "validate_jsonl",
    "validate_record",
]
