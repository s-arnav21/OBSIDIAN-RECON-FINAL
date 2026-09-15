"""Differential session-fixation and cookie security validation for normalized HTTP findings."""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult


VALIDATOR_ID = "generic-http-session-fixation"
VALIDATOR_NAME = "generic_http_session_fixation"
VALIDATION_METHOD = "session-cookie-security-differential"

SUPPORTED_METHODS = frozenset({"GET", "POST"})

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

_INSECURE_COOKIE_FLAGS = {
    "httponly": re.compile(r"set-cookie.*(?<!\bhttponly\b)", re.I),
    "secure": re.compile(r"set-cookie.*(?<!\bsecure\b)", re.I),
    "samesite": re.compile(r"set-cookie.*(?<!\bsamesite\b)", re.I),
}

_SESSION_IDENTIFIER_PATTERNS = (
    re.compile(r"^(?:session|jsessionid|aspsessionid|phpsessid|sid|connect\.sid)\s*=", re.I),
    re.compile(r"^\w*session\w*\s*=", re.I),
)


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str
    headers: Dict[str, str]
    set_cookies: List[str]
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
        "session_fixation", "session_fixation_attack",
        "cookie_security", "insecure_session_management",
        "session_hijacking",
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
    headers = dict(getattr(response, "headers", {}))
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")

    set_cookies = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            set_cookies.append(value)

    # Also check raw headers for set-cookie
    raw_headers = getattr(response, "headers", {})
    if hasattr(raw_headers, "get_list"):
        try:
            set_cookies = raw_headers.get_list("set-cookie")
        except Exception:
            pass

    return _ResponseObservation(
        status=status, text=text, headers=headers,
        set_cookies=set_cookies, attempts=attempts,
    )


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


def _analyze_cookie_security(set_cookies: List[str]) -> Dict[str, Any]:
    """Analyze Set-Cookie headers for security flags."""
    analysis = {
        "total_cookies": len(set_cookies),
        "session_cookies_found": [],
        "insecure_cookies": [],
        "missing_httponly": [],
        "missing_secure": [],
        "missing_samesite": [],
    }

    for cookie_header in set_cookies:
        lower = cookie_header.lower()
        is_session_cookie = any(
            pat.search(cookie_header) for pat in _SESSION_IDENTIFIER_PATTERNS
        )

        if is_session_cookie:
            cookie_name = cookie_header.split("=")[0].strip()
            analysis["session_cookies_found"].append(cookie_name)

            if "httponly" not in lower:
                analysis["missing_httponly"].append(cookie_name)
                analysis["insecure_cookies"].append(cookie_name)
            if "secure" not in lower:
                analysis["missing_secure"].append(cookie_name)
                if cookie_name not in analysis["insecure_cookies"]:
                    analysis["insecure_cookies"].append(cookie_name)
            if "samesite" not in lower:
                analysis["missing_samesite"].append(cookie_name)
                if cookie_name not in analysis["insecure_cookies"]:
                    analysis["insecure_cookies"].append(cookie_name)

    analysis["has_insecure_cookies"] = bool(analysis["insecure_cookies"])
    return analysis


def _detect_session_fixation(
    first_obs: _ResponseObservation,
    second_obs: _ResponseObservation,
) -> Dict[str, Any]:
    """Detect session fixation by comparing session IDs across requests."""
    result = {
        "first_request_cookies": first_obs.set_cookies,
        "second_request_cookies": second_obs.set_cookies,
        "session_id_changed": False,
        "fixation_possible": False,
    }

    first_sessions = [
        c for c in first_obs.set_cookies
        if any(pat.search(c) for pat in _SESSION_IDENTIFIER_PATTERNS)
    ]
    second_sessions = [
        c for c in second_obs.set_cookies
        if any(pat.search(c) for pat in _SESSION_IDENTIFIER_PATTERNS)
    ]

    if first_sessions and second_sessions:
        first_id = first_sessions[0].split(";")[0].split("=", 1)[1] if "=" in first_sessions[0] else ""
        second_id = second_sessions[0].split(";")[0].split("=", 1)[1] if "=" in second_sessions[0] else ""
        result["session_id_changed"] = first_id != second_id
        result["fixation_possible"] = first_id == second_id and bool(first_id)
    elif not first_sessions and not second_sessions:
        result["session_id_changed"] = True
        result["fixation_possible"] = False

    return result


def validate_generic_http_session_fixation(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Validate session fixation and cookie security configuration."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    # First request - observe session cookie behavior
    try:
        first_response = _send_probe(finding, session, url=url)
    except _ProbeRequestFailure as exc:
        return _manual_review(
            finding, "request_failed",
            evidence={"attempts": exc.attempts},
            error="bounded HTTP request failed",
        )

    if _waf_interference(first_response):
        return _manual_review(
            finding, "waf_or_filter_interference",
            evidence={"status": first_response.status},
        )

    # Second request - check session regeneration
    try:
        second_response = _send_probe(finding, session, url=url)
    except _ProbeRequestFailure as exc:
        return _manual_review(
            finding, "second_request_failed",
            evidence={"attempts": exc.attempts},
        )

    cookie_analysis = _analyze_cookie_security(first_response.set_cookies)
    fixation_analysis = _detect_session_fixation(first_response, second_response)

    issues_found = []

    if cookie_analysis["has_insecure_cookies"]:
        issues_found.append("insecure_cookie_flags")
    if cookie_analysis["missing_httponly"]:
        issues_found.append("missing_httponly")
    if cookie_analysis["missing_secure"]:
        issues_found.append("missing_secure")
    if cookie_analysis["missing_samesite"]:
        issues_found.append("missing_samesite")
    if fixation_analysis["fixation_possible"]:
        issues_found.append("session_fixation_possible")

    evidence = {
        **_context_evidence(finding),
        "first_request_status": first_response.status,
        "second_request_status": second_response.status,
        "cookie_analysis": cookie_analysis,
        "fixation_analysis": fixation_analysis,
        "issues_found": issues_found,
        "issue_count": len(issues_found),
    }

    if issues_found:
        severity = "high" if "session_fixation_possible" in issues_found else "medium"
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.88 if severity == "high" else 0.80,
            decision="confirmed",
            reason=f"session_security_issues_detected: {', '.join(issues_found)}",
            evidence=evidence,
        )

    return _result(
        finding,
        status=ValidationStatus.REJECTED,
        confidence=0.85,
        decision="rejected",
        reason="session_security_configuration_acceptable",
        evidence=evidence,
    )
