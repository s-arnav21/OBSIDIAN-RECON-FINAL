"""Differential Authentication Bypass validation for normalized HTTP findings."""

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


VALIDATOR_ID = "generic-http-auth-bypass"
VALIDATOR_NAME = "generic_http_auth_bypass"
VALIDATION_METHOD = "unauthenticated-access-differential"

SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})

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

_AUTH_REQUIRED_SIGNATURES = (
    re.compile(r"unauthorized", re.I),
    re.compile(r"not\s+authenticated", re.I),
    re.compile(r"login\s+required", re.I),
    re.compile(r"sign\s*in\s+to\s+continue", re.I),
    re.compile(r"session\s+expired", re.I),
    re.compile(r"access\s+token\s+missing", re.I),
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
    ))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def _context_evidence(finding: Finding) -> Dict[str, Any]:
    return {
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
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
        "auth_bypass", "authentication_bypass", "broken_authentication",
        "missing_authentication", "unauthenticated_access",
        "insecure_authentication",
    }:
        return "unexpected_vulnerability_type"
    if not finding.endpoint or not finding.endpoint.strip():
        return "missing_endpoint"
    if not finding.http_method:
        return "missing_http_method"
    if session is None:
        return "missing_scoped_http_session"
    return None


def _observe_response(response: Any, *, attempts: int) -> _ResponseObservation:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", None)
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")
    return _ResponseObservation(status=status, text=text, attempts=attempts)


def _send_probe(
    finding: Finding,
    session: Any,
    *,
    url: str,
) -> _ResponseObservation:
    transient_errors = (httpx.TransportError, ConnectionError, TimeoutError)
    for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
        try:
            response = session.request(
                finding.http_method or "GET",
                url,
                timeout=_REQUEST_TIMEOUT_SECONDS,
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


def _requires_auth(observation: _ResponseObservation) -> bool:
    if observation.status in {401, 403}:
        return True
    bounded = observation.text[:_ANALYSIS_CHARACTER_LIMIT]
    return any(sig.search(bounded) for sig in _AUTH_REQUIRED_SIGNATURES)


def validate_generic_http_auth_bypass(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Validate authentication bypass by testing unauthenticated access to protected endpoints."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    # Probe with clean session (no cookies/tokens)
    try:
        clean_response = _send_probe(finding, session, url=url)
    except _ProbeRequestFailure as exc:
        return _manual_review(
            finding, "request_failed",
            evidence={"attempts": exc.attempts},
            error="bounded HTTP request failed",
        )

    if _waf_interference(clean_response):
        return _manual_review(
            finding, "waf_or_filter_interference",
            evidence={"status": clean_response.status},
        )

    auth_required = _requires_auth(clean_response)
    accessible_without_auth = (
        200 <= clean_response.status < 400 and not auth_required
    )

    evidence = {
        **_context_evidence(finding),
        "unauthenticated_status": clean_response.status,
        "response_length": len(clean_response.text),
        "auth_required_detected": auth_required,
        "accessible_without_auth": accessible_without_auth,
    }

    if accessible_without_auth:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.80,
            decision="confirmed",
            reason="endpoint_accessible_without_authentication",
            evidence=evidence,
        )

    if auth_required:
        return _result(
            finding,
            status=ValidationStatus.REJECTED,
            confidence=0.85,
            decision="rejected",
            reason="authentication_enforcement_detected",
            evidence=evidence,
        )

    return _manual_review(
        finding, "ambiguous_authentication_state",
        evidence=evidence,
    )
