"""Fixed-token System Information Discovery simulation for the loopback demo."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlsplit

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult


VALIDATOR_ID = "controlled-http-system-information-discovery"
VALIDATOR_NAME = "controlled_http_system_information_discovery"
VALIDATION_METHOD = "synthetic-system-information-marker-differential"

BASELINE_DISCOVERY_TOKEN = "obsidian-system-information-baseline-v1"
DISCOVERY_PROBE_TOKEN = "obsidian-system-information-probe-v1"
CONTROL_DISCOVERY_TOKEN = "obsidian-system-information-control-v1"
SYSTEM_INFORMATION_MARKER = "OBSIDIAN_SYNTHETIC_SYSTEM_INFORMATION_91C4E"


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str


def _context_evidence(finding: Finding) -> Dict[str, Any]:
    return {
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter_name": finding.parameter_name,
        "parameter_location": finding.parameter_location,
        "simulation_scope": "fixed_loopback_fixture_only",
        "real_system_information_accessed": False,
        "external_requests_performed": False,
    }


def _result(
    finding: Finding,
    *,
    status: str,
    confidence: float,
    decision: str,
    reason: str,
    evidence: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> ValidationResult:
    return ValidationResult(
        status=status,
        confidence=confidence,
        validator=VALIDATOR_NAME,
        method=VALIDATION_METHOD,
        evidence={
            **_context_evidence(finding),
            **(evidence or {}),
            "decision": decision,
            "reason": reason,
        },
        error=error,
    )


def _manual_review(
    finding: Finding,
    reason: str,
    *,
    evidence: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> ValidationResult:
    return _result(
        finding,
        status=ValidationStatus.MANUAL_REVIEW,
        confidence=STATUS_WEIGHT[ValidationStatus.MANUAL_REVIEW],
        decision="inconclusive",
        reason=reason,
        evidence=evidence,
        error=error,
    )


def _is_loopback_target(target: str) -> bool:
    try:
        hostname = urlsplit(target).hostname
    except ValueError:
        return False
    if hostname == "localhost":
        return True
    try:
        return bool(hostname) and ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _resolve_endpoint_url(finding: Finding) -> str:
    endpoint = (finding.endpoint or "").strip()
    if not endpoint:
        raise ValueError("missing_endpoint")

    endpoint_parts = urlsplit(endpoint)
    if endpoint_parts.scheme or endpoint_parts.netloc:
        target_parts = urlsplit(finding.target)
        endpoint_origin = (
            endpoint_parts.scheme.lower(),
            endpoint_parts.hostname,
            endpoint_parts.port,
        )
        target_origin = (
            target_parts.scheme.lower(),
            target_parts.hostname,
            target_parts.port,
        )
        if endpoint_origin != target_origin:
            raise ValueError("endpoint_origin_mismatch")
        return endpoint

    return urljoin(f"{finding.target.rstrip('/')}/", endpoint.lstrip("/"))


def _validate_context(finding: Finding, session: Any) -> Optional[str]:
    normalized_type = finding.vulnerability_type.lower().replace("-", "_")
    if normalized_type != "system_information_discovery":
        return "unexpected_vulnerability_type"
    if not _is_loopback_target(finding.target):
        return "controlled_simulation_requires_loopback"
    if not finding.endpoint or not finding.endpoint.strip():
        return "missing_endpoint"
    if finding.http_method != "POST":
        return "unsupported_http_method"
    if not finding.parameter_name or not finding.parameter_name.strip():
        return "missing_parameter_name"
    if finding.parameter_location != "form":
        return "unsupported_parameter_location"
    if session is None:
        return "missing_scoped_http_session"
    return None


def _observe_response(response: Any) -> _ResponseObservation:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", None)
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")
    return _ResponseObservation(status=status, text=text)


def _send_token(
    session: Any,
    *,
    url: str,
    parameter_name: str,
    token: str,
) -> _ResponseObservation:
    return _observe_response(
        session.post(url, data={parameter_name: token})
    )


def validate_controlled_system_information_discovery(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Validate only the loopback fixture's fixed synthetic discovery protocol."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
        parameter_name = finding.parameter_name or ""
        baseline = _send_token(
            session,
            url=url,
            parameter_name=parameter_name,
            token=BASELINE_DISCOVERY_TOKEN,
        )
        probe = _send_token(
            session,
            url=url,
            parameter_name=parameter_name,
            token=DISCOVERY_PROBE_TOKEN,
        )
        control = _send_token(
            session,
            url=url,
            parameter_name=parameter_name,
            token=CONTROL_DISCOVERY_TOKEN,
        )
    except Exception:
        return _manual_review(
            finding,
            "http_request_failed",
            error="controlled HTTP request failed",
        )

    baseline_marker_present = SYSTEM_INFORMATION_MARKER in baseline.text
    discovery_marker_present = SYSTEM_INFORMATION_MARKER in probe.text
    control_marker_present = SYSTEM_INFORMATION_MARKER in control.text
    evidence = {
        "baseline_status": baseline.status,
        "probe_status": probe.status,
        "control_status": control.status,
        "baseline_length": len(baseline.text),
        "probe_length": len(probe.text),
        "control_length": len(control.text),
        "baseline_marker_present": baseline_marker_present,
        "discovery_marker_present": discovery_marker_present,
        "control_marker_present": control_marker_present,
    }

    statuses = {baseline.status, probe.status, control.status}
    if not all(200 <= status < 300 for status in statuses):
        return _manual_review(
            finding,
            "non_success_http_status",
            evidence=evidence,
        )
    if len(statuses) != 1:
        return _manual_review(
            finding,
            "inconsistent_http_status",
            evidence=evidence,
        )
    if baseline_marker_present or control_marker_present:
        return _manual_review(
            finding,
            "discovery_marker_not_unique_to_probe",
            evidence=evidence,
        )
    if discovery_marker_present:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.9,
            decision="confirmed",
            reason="unique_synthetic_system_information_marker_observed",
            evidence=evidence,
        )
    return _result(
        finding,
        status=ValidationStatus.REJECTED,
        confidence=0.9,
        decision="rejected",
        reason="synthetic_system_information_marker_not_observed",
        evidence=evidence,
    )
