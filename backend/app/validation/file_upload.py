"""Differential unrestricted file upload validation for normalized HTTP findings."""

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


VALIDATOR_ID = "generic-http-file-upload"
VALIDATOR_NAME = "generic_http_file_upload"
VALIDATION_METHOD = "unrestricted-upload-differential"

SUPPORTED_METHODS = frozenset({"POST", "PUT", "PATCH"})

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

_UPLOAD_REJECTION_SIGNATURES = (
    re.compile(r"file.?type.?not.?allowed", re.I),
    re.compile(r"invalid.?file.?extension", re.I),
    re.compile(r"upload.?denied", re.I),
    re.compile(r"content.?type.?not.?allowed", re.I),
    re.compile(r"file.?upload.?error", re.I),
    re.compile(r"forbidden.?file", re.I),
)

_UPLOAD_SUCCESS_SIGNATURES = (
    re.compile(r"upload.?successful", re.I),
    re.compile(r"file.?uploaded", re.I),
    re.compile(r"successfully.?uploaded", re.I),
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
        "unrestricted_file_upload", "file_upload",
        "arbitrary_file_upload", " unrestricted file upload",
    }:
        return "unexpected_vulnerability_type"
    if not finding.endpoint or not finding.endpoint.strip():
        return "missing_endpoint"
    if not finding.http_method:
        return "missing_http_method"
    if not finding.parameter_name or not finding.parameter_name.strip():
        return "missing_parameter_name"
    if session is None:
        return "missing_scoped_http_session"
    return None


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


def _send_upload_probe(
    finding: Finding,
    session: Any,
    *,
    url: str,
    filename: str,
    content: bytes,
    content_type: str,
) -> _ResponseObservation:
    parameter_name = finding.parameter_name or "file"
    files = {parameter_name: (filename, content, content_type)}
    transient_errors = (httpx.TransportError, ConnectionError, TimeoutError)
    for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
        try:
            response = session.request(
                finding.http_method or "POST",
                url,
                timeout=_REQUEST_TIMEOUT_SECONDS,
                files=files,
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


def _is_rejection(text: str) -> bool:
    bounded = text[:_ANALYSIS_CHARACTER_LIMIT]
    return any(sig.search(bounded) for sig in _UPLOAD_REJECTION_SIGNATURES)


def _is_success(text: str) -> bool:
    bounded = text[:_ANALYSIS_CHARACTER_LIMIT]
    return any(sig.search(bounded) for sig in _UPLOAD_SUCCESS_SIGNATURES)


def validate_generic_http_file_upload(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Validate unrestricted file upload using benign probe uploads."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    root = _finding_marker_root(finding)

    upload_tests = [
        ("safe_txt", f"or-upload-{root}.txt", b"obsidian-upload-probe-safe", "text/plain"),
        ("safe_png", f"or-upload-{root}.png", b"\x89PNG\r\n\x1a\n\x00\x00", "image/png"),
        ("extreme_svg", f"or-upload-{root}.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><text>obsidian</text></svg>', "image/svg+xml"),
    ]

    probe_results = []
    any_accepted = False
    acceptance_count = 0

    for probe_name, filename, content, content_type in upload_tests:
        try:
            obs = _send_upload_probe(
                finding, session, url=url,
                filename=filename, content=content, content_type=content_type,
            )
        except _ProbeRequestFailure:
            probe_results.append({"probe": probe_name, "status": "error"})
            continue

        if _waf_interference(obs):
            probe_results.append({
                "probe": probe_name, "status": "waf_blocked",
                "http_status": obs.status,
            })
            continue

        rejected = _is_rejection(obs.text)
        accepted = (
            (200 <= obs.status < 300 or obs.status in {301, 302})
            and not rejected
        )

        if accepted:
            any_accepted = True
            acceptance_count += 1

        probe_results.append({
            "probe": probe_name,
            "status": "accepted" if accepted else ("rejected" if rejected else "unknown"),
            "http_status": obs.status,
            "response_length": len(obs.text),
            "rejection_detected": rejected,
        })

    evidence = {
        **_context_evidence(finding),
        "probes": probe_results,
        "any_accepted": any_accepted,
        "acceptance_count": acceptance_count,
        "total_probes": len(upload_tests),
    }

    if any_accepted and acceptance_count >= 2:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.85,
            decision="confirmed",
            reason="multiple_file_types_accepted_without_restriction",
            evidence=evidence,
        )

    if any_accepted:
        return _manual_review(
            finding, "partial_upload_acceptance_needs_analysis",
            evidence=evidence,
        )

    return _result(
        finding,
        status=ValidationStatus.REJECTED,
        confidence=0.85,
        decision="rejected",
        reason="all_upload_probes_rejected",
        evidence=evidence,
    )
