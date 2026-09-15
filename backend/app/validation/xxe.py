"""Differential XML External Entity (XXE) validation for normalized HTTP findings."""

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


VALIDATOR_ID = "generic-http-xxe"
VALIDATOR_NAME = "generic_http_xxe"
VALIDATION_METHOD = "controlled-entity-reference-differential"

SUPPORTED_METHODS = frozenset({"POST", "PUT", "PATCH"})
SUPPORTED_PARAMETER_LOCATIONS = frozenset({"json", "form"})

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

_XXE_PROLOGUE_CONTENT_TYPES = frozenset({
    "application/xml", "text/xml", "application/xhtml+xml",
    "application/soap+xml",
})

_XXE_ENTITY_SIGNATURES = (
    re.compile(r"ENTITY\s+\w+\s+SYSTEM", re.I),
    re.compile(r"<!ENTITY\s+%\s+\w+\s+SYSTEM", re.I),
)

_XXE_ERROR_SIGNATURES = (
    re.compile(r"xml parsing error", re.I),
    re.compile(r"saxParseException", re.I),
    re.compile(r"org\.xml\.sax", re.I),
    re.compile(r"xmlreader", re.I),
    re.compile(r"lxml\.etree", re.I),
    re.compile(r"libxml", re.I),
    re.compile(r"xml parser", re.I),
)


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str
    content_type: str
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
        "xxe", "xml_external_entity", "xml_injection",
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
    if finding.parameter_location not in finding.http_request_context:
        return "insufficient_original_request_context"
    if session is None:
        return "missing_scoped_http_session"
    if not callable(getattr(session, "request", None)):
        return "scoped_http_session_missing_request_interface"
    return None


def _xxe_payloads(root: str) -> list[tuple[str, str]]:
    canary = f"or-xxe-canary-{root}"
    negative = f"or-xxe-negative-{root}"
    return [
        (
            "entity_probe",
            f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///dev/null">]><data>&xxe;</data>',
        ),
        (
            "parameter_entity",
            f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY % xxe SYSTEM "file:///dev/null">%xxe;]><data>test</data>',
        ),
        (
            "error_based",
            f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/nonexistent_{canary}">]><data>&xxe;</data>',
        ),
        ("safe_control", f'<?xml version="1.0" encoding="UTF-8"?><data>{negative}</data>'),
    ]


def _observe_response(response: Any, *, attempts: int) -> _ResponseObservation:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", None)
    headers = getattr(response, "headers", {})
    content_type = ""
    if hasattr(headers, "get"):
        content_type = headers.get("content-type", "") or headers.get("Content-Type", "")
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")
    return _ResponseObservation(
        status=status,
        text=text,
        content_type=content_type.lower() if isinstance(content_type, str) else str(content_type).lower(),
        attempts=attempts,
    )


def _send_probe(
    finding: Finding,
    session: Any,
    *,
    url: str,
    payload: str,
) -> _ResponseObservation:
    kwargs: Dict[str, Any] = {}
    headers: Dict[str, str] = {}
    content_type_header = "application/xml"

    original_context = finding.http_request_context.get(finding.parameter_location or "", {})
    if finding.parameter_location == "json":
        kwargs["json"] = {finding.parameter_name: payload}
        content_type_header = "application/json"
    elif finding.parameter_location == "form":
        kwargs["data"] = {finding.parameter_name: payload}
        content_type_header = "application/x-www-form-urlencoded"

    headers["Content-Type"] = content_type_header

    transient_errors = (httpx.TransportError, ConnectionError, TimeoutError)
    for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
        try:
            response = session.request(
                finding.http_method or "POST",
                url,
                timeout=_REQUEST_TIMEOUT_SECONDS,
                headers=headers,
                **kwargs,
            )
            return _observe_response(response, attempts=attempt)
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


def _has_xxe_error(text: str) -> bool:
    bounded = text[:_ANALYSIS_CHARACTER_LIMIT]
    return any(sig.search(bounded) for sig in _XXE_ERROR_SIGNATURES)


def validate_generic_http_xxe(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Validate XXE using controlled entity reference injection probes."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    root = _finding_marker_root(finding)
    payloads = _xxe_payloads(root)

    # Baseline probe with safe XML
    safe_payload = next(p for name, p in payloads if name == "safe_control")
    try:
        baseline = _send_probe(finding, session, url=url, payload=safe_payload)
    except _ProbeRequestFailure as exc:
        return _manual_review(
            finding, "baseline_request_failed",
            evidence={"attempts": exc.attempts},
            error="bounded HTTP request failed",
        )

    if _waf_interference(baseline):
        return _manual_review(
            finding, "waf_or_filter_interference",
            evidence={"baseline_status": baseline.status},
        )

    probe_results = []
    xxe_detected = False
    detection_method = None

    for probe_name, payload in payloads:
        if probe_name == "safe_control":
            continue
        try:
            observation = _send_probe(finding, session, url=url, payload=payload)
        except _ProbeRequestFailure:
            probe_results.append({"probe": probe_name, "status": "error"})
            continue

        if _waf_interference(observation):
            probe_results.append({
                "probe": probe_name, "status": "waf_blocked",
                "http_status": observation.status,
            })
            continue

        has_error = _has_xxe_error(observation.text)
        status_different = observation.status != baseline.status
        error_based_signal = has_error and status_different

        probe_results.append({
            "probe": probe_name,
            "status": "confirmed" if error_based_signal else "negative",
            "http_status": observation.status,
            "response_length": len(observation.text),
            "xml_error_detected": has_error,
            "status_changed": status_different,
        })

        if error_based_signal:
            xxe_detected = True
            detection_method = probe_name
            break

    evidence = {
        **_context_evidence(finding),
        "baseline_status": baseline.status,
        "baseline_length": len(baseline.text),
        "probes": probe_results,
        "xxe_detected": xxe_detected,
        "detection_method": detection_method,
    }

    if xxe_detected:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.87,
            decision="confirmed",
            reason=f"xml_external_entity_{detection_method}_confirmed",
            evidence=evidence,
        )

    return _result(
        finding,
        status=ValidationStatus.REJECTED,
        confidence=0.85,
        decision="rejected",
        reason="no_xxe_signal_observed",
        evidence=evidence,
    )
