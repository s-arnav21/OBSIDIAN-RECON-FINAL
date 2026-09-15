"""Differential Local File Inclusion (LFI) validation for normalized HTTP findings."""

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


VALIDATOR_ID = "generic-http-lfi"
VALIDATOR_NAME = "generic_http_lfi"
VALIDATION_METHOD = "controlled-canary-file-differential"

SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})
SUPPORTED_PARAMETER_LOCATIONS = frozenset({
    "query", "form", "json", "cookie",
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
    re.compile(r"temporarily rate[ -]?limited", re.I),
)

_LFI_PROBE_TRAVERSALS = (
    ("null_byte", "%00"),
    ("single_traverse", "../"),
    ("double_traverse", "../../"),
    ("linux_passwd", "../../../../../../etc/passwd"),
    ("linux_passwd_url", "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
    ("windows_hosts", "..\\..\\..\\..\\..\\..\\windows\\win.ini"),
)

_LFI_MARKER = "OBSIDIAN_LFI_CANARY_{kind}_{root}"
_LFI_CANARY_CONTENT = "obsidian-lfi-canary-{kind}-{root}"

_LINUX_PASSWD_SIGNATURES = (
    re.compile(r"root:.*:0:0:"),
    re.compile(r"\bdaemon\b.*:\d+:\d+:"),
    re.compile(r"\bnobody\b.*:\d+:\d+:"),
)
_WINDOWS_INI_SIGNATURES = (
    re.compile(r"\[fonts\]", re.I),
    re.compile(r"\[extensions\]", re.I),
    re.compile(r"\[mci extensions\]", re.I),
)


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str
    elapsed_seconds: float
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
        "local_file_inclusion", "lfi", "path_traversal",
        "directory_traversal", "file_inclusion",
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


def _request_kwargs(finding: Finding, value: str) -> Dict[str, Any]:
    location = finding.parameter_location or ""
    parameter_name = finding.parameter_name or ""
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


def _observe_response(response: Any, *, measured: float, attempts: int) -> _ResponseObservation:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", None)
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")
    return _ResponseObservation(
        status=status,
        text=text,
        elapsed_seconds=round(measured, 6),
        attempts=attempts,
    )


def _send_probe(
    finding: Finding,
    session: Any,
    *,
    url: str,
    value: str,
) -> _ResponseObservation:
    kwargs = _request_kwargs(finding, value)
    transient_errors = (httpx.TransportError, ConnectionError, TimeoutError)
    for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
        started = time.monotonic()
        try:
            response = session.request(
                finding.http_method or "",
                url,
                timeout=_REQUEST_TIMEOUT_SECONDS,
                **kwargs,
            )
            return _observe_response(
                response,
                measured=time.monotonic() - started,
                attempts=attempt,
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


def _detect_sensitive_file_content(text: str) -> Optional[str]:
    bounded = text[:_ANALYSIS_CHARACTER_LIMIT]
    for sig in _LINUX_PASSWD_SIGNATURES:
        if sig.search(bounded):
            return "linux_passwd_content"
    for sig in _WINDOWS_INI_SIGNATURES:
        if sig.search(bounded):
            return "windows_ini_content"
    return None


def validate_generic_http_lfi(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Validate LFI using traversal probes and sensitive-file differential analysis."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    root = _finding_marker_root(finding)

    # Get baseline with a safe random-ish value
    try:
        baseline = _send_probe(
            finding, session, url=url, value=f"orx-lfi-baseline-{root}",
        )
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
    if not 200 <= baseline.status < 300:
        return _manual_review(
            finding, "non_success_baseline_status",
            evidence={"baseline_status": baseline.status},
        )

    probe_results = []
    sensitive_file_detected = False
    detection_method = None

    for probe_name, probe_value in _LFI_PROBE_TRAVERSALS:
        try:
            observation = _send_probe(
                finding, session, url=url, value=probe_value,
            )
        except _ProbeRequestFailure:
            probe_results.append({
                "probe": probe_name, "status": "error",
            })
            continue

        if _waf_interference(observation):
            probe_results.append({
                "probe": probe_name, "status": "waf_blocked",
                "http_status": observation.status,
            })
            continue

        content_signal = _detect_sensitive_file_content(observation.text)
        if content_signal:
            sensitive_file_detected = True
            detection_method = content_signal
            probe_results.append({
                "probe": probe_name,
                "status": "confirmed",
                "http_status": observation.status,
                "response_length": len(observation.text),
                "signal": content_signal,
            })
            break

        probe_results.append({
            "probe": probe_name,
            "status": "negative",
            "http_status": observation.status,
            "response_length": len(observation.text),
        })

    evidence = {
        **_context_evidence(finding),
        "baseline_status": baseline.status,
        "baseline_length": len(baseline.text),
        "probes": probe_results,
        "sensitive_file_detected": sensitive_file_detected,
        "detection_method": detection_method,
    }

    if sensitive_file_detected:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.88,
            decision="confirmed",
            reason=f"sensitive_file_content_observed_via_{detection_method}",
            evidence=evidence,
        )

    return _result(
        finding,
        status=ValidationStatus.REJECTED,
        confidence=0.85,
        decision="rejected",
        reason="no_sensitive_file_content_observed",
        evidence=evidence,
    )
