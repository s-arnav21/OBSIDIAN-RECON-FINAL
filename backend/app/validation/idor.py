"""Differential Insecure Direct Object Reference (IDOR) validation for normalized HTTP findings."""

from __future__ import annotations

import hashlib
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult


VALIDATOR_ID = "generic-http-idor"
VALIDATOR_NAME = "generic_http_idor"
VALIDATION_METHOD = "object-reference-differential"

SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
SUPPORTED_PARAMETER_LOCATIONS = frozenset({
    "query", "form", "json", "path", "cookie",
})

_REQUEST_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_ATTEMPTS = 3
_RETRY_BACKOFF_SECONDS = 0.05
_ANALYSIS_CHARACTER_LIMIT = 100_000
_WAF_STATUS_CODES = frozenset({403, 406, 429})
_WAF_TEXT_PATTERNS = (
    re.compile(r"web application firewall", re.I),
    re.compile(r"request (?:was )?blocked", re.I),
    re.compile(r"blocked by (?:a )?security (?:rule|policy)", re.I),
    re.compile(r"mod_security|modsecurity", re.I),
    re.compile(r"cloudflare ray id", re.I),
)

_UNAUTHORIZED_SIGNATURES = (
    re.compile(r"unauthorized", re.I),
    re.compile(r"not\s+authenticated", re.I),
    re.compile(r"access\s+denied", re.I),
    re.compile(r"permission\s+denied", re.I),
    re.compile(r"login\s+required", re.I),
    re.compile(r"sign\s*in", re.I),
)


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str
    attempts: int


class _ProbeRequestFailure(RuntimeError):
    def __init__(self, attempts: int) -> None:
        super().__init__("bounded probe request failed")
        self.attempts = attempts


def _finding_marker_root(finding: Finding) -> str:
    identity = "\x1f".join((
        finding.finding_id,
        finding.scan_id,
        finding.asset_id,
        finding.target,
        finding.endpoint or "",
        finding.http_method or "",
        finding.parameter_location or "",
        finding.parameter_name or "",
    ))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def _context_evidence(finding: Finding) -> Dict[str, Any]:
    return {
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter_name": finding.parameter_name,
        "parameter_location": finding.parameter_location,
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
            endpoint_parts.port or (
                443 if endpoint_parts.scheme.lower() == "https" else 80
            ),
        )
        target_origin = (
            target_parts.scheme.lower(),
            target_parts.hostname,
            target_parts.port or (
                443 if target_parts.scheme.lower() == "https" else 80
            ),
        )
        if endpoint_origin != target_origin:
            raise ValueError("endpoint_origin_mismatch")
        return endpoint
    return urljoin(f"{finding.target.rstrip('/')}/", endpoint.lstrip("/"))


def _validate_context(finding: Finding, session: Any) -> Optional[str]:
    normalized_type = finding.vulnerability_type.lower().replace("-", "_")
    if normalized_type not in {
        "idor", "insecure_direct_object_reference",
        "broken_access_control", "authorization_bypass",
    }:
        return "unexpected_vulnerability_type"
    if not finding.endpoint or not finding.endpoint.strip():
        return "missing_endpoint"
    if not finding.http_method:
        return "missing_http_method"
    if not finding.parameter_name or not finding.parameter_name.strip():
        return "missing_parameter_name"
    if not finding.parameter_location:
        return "missing_parameter_location"
    if finding.http_method not in SUPPORTED_METHODS:
        return "unsupported_http_method"
    if finding.parameter_location not in SUPPORTED_PARAMETER_LOCATIONS:
        return "unsupported_parameter_location"
    if finding.parameter_location in {"form", "json", "cookie"}:
        if finding.parameter_location not in finding.http_request_context:
            return "insufficient_original_request_context"
    if session is None:
        return "missing_scoped_http_session"
    if not callable(getattr(session, "request", None)):
        return "scoped_http_session_missing_request_interface"
    return None


def _request_kwargs_with_value(
    finding: Finding, value: str, *, override_name: Optional[str] = None,
) -> Dict[str, Any]:
    location = finding.parameter_location or ""
    parameter_name = override_name or finding.parameter_name or ""
    original = deepcopy(finding.http_request_context.get(location, {}))
    original[parameter_name] = value
    if location == "query":
        return {"params": original}
    if location == "form":
        return {"data": original}
    if location == "json":
        return {"json": original}
    if location == "cookie":
        return {"cookies": original}
    raise ValueError("unsupported_parameter_location")


def _send_probe(
    finding: Finding,
    session: Any,
    *,
    url: str,
    value: str,
) -> _ResponseObservation:
    kwargs = _request_kwargs_with_value(finding, value)
    transient_errors = (httpx.TransportError, ConnectionError, TimeoutError)
    for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
        try:
            response = session.request(
                finding.http_method or "",
                url,
                timeout=_REQUEST_TIMEOUT_SECONDS,
                **kwargs,
            )
            status = getattr(response, "status_code", None)
            text = getattr(response, "text", None)
            if isinstance(status, bool) or not isinstance(status, int):
                raise TypeError("HTTP response status_code must be an integer")
            if not isinstance(text, str):
                raise TypeError("HTTP response text must be a string")
            return _ResponseObservation(
                status=status, text=text, attempts=attempt,
            )
        except transient_errors as exc:
            if attempt >= _MAX_REQUEST_ATTEMPTS:
                raise _ProbeRequestFailure(attempt) from exc
            time.sleep(_RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))
        except Exception as exc:
            raise _ProbeRequestFailure(attempt) from exc
    raise _ProbeRequestFailure(_MAX_REQUEST_ATTEMPTS)


def _waf_interference(observation: _ResponseObservation) -> bool:
    if observation.status in _WAF_STATUS_CODES:
        return True
    bounded = observation.text[:_ANALYSIS_CHARACTER_LIMIT]
    return any(pattern.search(bounded) for pattern in _WAF_TEXT_PATTERNS)


def _is_unauthorized_response(observation: _ResponseObservation) -> bool:
    if observation.status in {401, 403}:
        return True
    bounded = observation.text[:_ANALYSIS_CHARACTER_LIMIT]
    return any(sig.search(bounded) for sig in _UNAUTHORIZED_SIGNATURES)


def _idor_probe_values(finding: Finding) -> list[tuple[str, str]]:
    root = _finding_marker_root(finding)
    original_value = finding.http_request_context.get(
        finding.parameter_location or "", {}
    ).get(finding.parameter_name or "", "")
    return [
        ("original", str(original_value)),
        ("incremented", "2"),
        ("decremented", "0"),
        ("large_id", "999999"),
        ("alt_numeric", "1"),
        ("string_id", f"or-idor-{root}"),
    ]


def validate_generic_http_idor(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Validate IDOR using object-reference differential analysis across IDs."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    probes = _idor_probe_values(finding)
    observations: list[tuple[str, _ResponseObservation]] = []

    for probe_name, probe_value in probes:
        try:
            obs = _send_probe(finding, session, url=url, value=probe_value)
        except _ProbeRequestFailure:
            observations.append((probe_name, _ResponseObservation(
                status=0, text="", attempts=0,
            )))
            continue
        observations.append((probe_name, obs))

    if all(obs.status == 0 for _, obs in observations):
        return _manual_review(
            finding, "all_probes_failed",
            error="all bounded IDOR probe requests failed",
        )

    baseline = observations[0][1]
    if _waf_interference(baseline):
        return _manual_review(
            finding, "waf_or_filter_interference",
            evidence={"baseline_status": baseline.status},
        )

    # Analyze differential access patterns
    accessible_with_different_id = False
    consistent_unauthorized = True
    probe_details = []

    for probe_name, obs in observations:
        if obs.status == 0:
            probe_details.append({"probe": probe_name, "status": "error"})
            continue

        if _waf_interference(obs):
            probe_details.append({
                "probe": probe_name, "status": "waf_blocked",
                "http_status": obs.status,
            })
            continue

        is_unauth = _is_unauthorized_response(obs)
        consistent_unauthorized = consistent_unauthorized and is_unauth

        probe_details.append({
            "probe": probe_name,
            "http_status": obs.status,
            "response_length": len(obs.text),
            "unauthorized_signal": is_unauth,
        })

        if (
            probe_name not in ("original",)
            and 200 <= obs.status < 300
            and not is_unauth
            and obs.status == baseline.status
            and len(obs.text) > 0
        ):
            accessible_with_different_id = True

    evidence = {
        **_context_evidence(finding),
        "baseline_status": baseline.status,
        "probes": probe_details,
        "accessible_with_different_id": accessible_with_different_id,
        "consistent_unauthorized": consistent_unauthorized,
    }

    if accessible_with_different_id:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.82,
            decision="confirmed",
            reason="object_accessible_with_alternate_identifier",
            evidence=evidence,
        )

    if consistent_unauthorized:
        return _result(
            finding,
            status=ValidationStatus.REJECTED,
            confidence=0.88,
            decision="rejected",
            reason="consistent_unauthorized_across_identifiers",
            evidence=evidence,
        )

    return _manual_review(
        finding, "mixed_access_patterns_require_analysis",
        evidence=evidence,
    )
