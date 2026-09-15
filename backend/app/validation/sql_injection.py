"""Conservative differential validation for normalized HTTP SQLi findings."""

from __future__ import annotations

import math
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from difflib import SequenceMatcher
from numbers import Real
from typing import Any, Dict, Mapping, Optional, Sequence
from urllib.parse import urljoin, urlsplit

import httpx

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult
from app.validation.tool_confirmation import sqlmap_confirmation


VALIDATOR_ID = "generic-http-sqli"
VALIDATOR_NAME = "generic_http_sqli"
VALIDATION_METHOD = "multi-method deterministic SQLi"

SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})
SUPPORTED_PARAMETER_LOCATIONS = frozenset({
    "query", "form", "json", "cookie", "header",
})

# These fixed probes are deliberately internal. Findings and callers cannot
# supply or override validation payloads.
_CONTROL_VALUE = "1"
_BOOLEAN_PROBE_PAIRS = (
    ("1 AND 1=1", "1 AND 1=2"),
    ("1 AND 'x'='x'", "1 AND 'x'='y'"),
    ("0 OR 1=1 AND 1=1", "0 OR 1=1 AND 1=2"),
)
# Compatibility aliases used by presentation code and existing imports.
_TRUE_PROBE_VALUE, _FALSE_PROBE_VALUE = _BOOLEAN_PROBE_PAIRS[0]

_ERROR_PROBES = (
    ("unterminated_single_quote", "1'"),
    ("unterminated_double_quote", '1"'),
)
_CONTROLLED_DELAY_SECONDS = 3.0
_TIMING_PROBES = (
    ("mysql", "1 AND SLEEP(3)"),
    ("postgresql", "1; SELECT pg_sleep(3)"),
    ("mssql", "1; WAITFOR DELAY '0:0:3'"),
)

_CONFIRMED_BASELINE_TRUE_MIN = 0.90
_CONFIRMED_BASELINE_FALSE_MAX = 0.70
_CONFIRMED_SIMILARITY_DELTA_MIN = 0.20
_CONFIRMED_TRUE_FALSE_MAX = 0.75

_REJECTED_TRUE_FALSE_MIN = 0.95
_REJECTED_DELTA_MAX = 0.05
_BOOLEAN_CONFIRMING_PAIRS_REQUIRED = 2

# Bound SequenceMatcher work on unexpectedly large responses.
_COMPARISON_CHARACTER_LIMIT = 100_000
_REQUEST_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_ATTEMPTS = 3
_RETRY_BACKOFF_SECONDS = 0.05
_TIMING_BASELINE_SAMPLES = 2
_TIMING_REPETITIONS = 2
_TIMING_BASELINE_MAX_SECONDS = 1.5
_TIMING_BASELINE_JITTER_MAX_SECONDS = 0.75
_TIMING_CONFIRMATION_FRACTION = 0.80

_METHOD_CONFIDENCE = {
    "boolean-response-differential": 0.85,
    "error-based": 0.80,
    "time-based-blind": 0.90,
}
_CORROBORATION_BONUS = 0.04

_ERROR_SIGNATURES = {
    "mysql": (
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning:\s*(?:mysql|mysqli)", re.I),
        re.compile(r"mysqli_sql_exception", re.I),
    ),
    "postgresql": (
        re.compile(r"postgresql.*error", re.I),
        re.compile(r"pg::syntaxerror", re.I),
        re.compile(r"unterminated quoted string", re.I),
    ),
    "mssql": (
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"microsoft ole db provider for sql server", re.I),
        re.compile(r"sql server.*error", re.I),
    ),
    "oracle": (re.compile(r"\bORA-\d{5}\b", re.I),),
    "sqlite": (
        re.compile(r"sqlite3?\.operationalerror", re.I),
        re.compile(r"sqlite(?:3)?[_ ](?:error|exception)", re.I),
        re.compile(r"sqlite.*syntax error", re.I),
    ),
    "db2": (
        re.compile(r"\bSQLCODE\s*[=:]", re.I),
        re.compile(r"\bDB2 SQL error\b", re.I),
    ),
    "firebird": (
        re.compile(r"dynamic sql error", re.I),
        re.compile(r"firebird.*error", re.I),
    ),
}

_WAF_TEXT_PATTERNS = (
    re.compile(r"web application firewall", re.I),
    re.compile(r"request (?:was )?blocked", re.I),
    re.compile(r"blocked by (?:a )?security (?:rule|policy)", re.I),
    re.compile(r"mod_security|modsecurity", re.I),
    re.compile(r"cloudflare ray id", re.I),
    re.compile(r"temporarily rate[ -]?limited", re.I),
)
_WAF_STATUS_CODES = frozenset({403, 406, 429})

_DYNAMIC_INPUT_RE = re.compile(
    r"(?P<prefix><input\b[^>]*\bname\s*=\s*['\"]"
    r"(?:[^'\"]*(?:csrf|nonce|token|viewstate|cache[_-]?bust)[^'\"]*)"
    r"['\"][^>]*\bvalue\s*=\s*['\"])[^'\"]*(?P<suffix>['\"])",
    re.I,
)
_DYNAMIC_ATTRIBUTE_RE = re.compile(
    r"(?P<prefix>\b(?:csrf|nonce|token|viewstate|cache[_-]?bust)"
    r"(?:[_-]?(?:token|value))?\s*[=:]\s*['\"]?)[^'\"\s<>&]+",
    re.I,
)
_ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_NAMED_TIMESTAMP_RE = re.compile(
    r"(?P<prefix>\b(?:timestamp|generated_at|updated_at|request_time|cache_bust)"
    r"\s*[=:]\s*['\"]?)\d{10,13}\b",
    re.I,
)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.I,
)


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str
    elapsed_seconds: float
    attempts: int


@dataclass(frozen=True)
class _MethodResult:
    state: str
    evidence: Dict[str, Any]
    waf_or_filter_interference: bool = False


class _ProbeRequestFailure(RuntimeError):
    def __init__(self, attempts: int) -> None:
        super().__init__("bounded probe request failed")
        self.attempts = attempts


def _context_evidence(finding: Finding) -> Dict[str, Any]:
    return {
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter_name": finding.parameter_name,
        "parameter_location": finding.parameter_location,
    }


def _real_tool_summary(v: Any) -> Dict[str, Any]:
    return {
        "tool": getattr(v, "tool", "unknown"),
        "available": getattr(v, "available", False),
        "ran": getattr(v, "ran", False),
        "confirmed": getattr(v, "confirmed", False),
        "not_vulnerable": getattr(v, "not_vulnerable", False),
        "timed_out": getattr(v, "timed_out", False),
        "error": getattr(v, "error", None),
        "dbms": getattr(v, "dbms", None),
        "databases": getattr(v, "databases", []),
        "duration_seconds": getattr(v, "duration_seconds", None),
    }


def _manual_review(
    finding: Finding,
    reason: str,
    *,
    evidence: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> ValidationResult:
    return ValidationResult(
        status=ValidationStatus.MANUAL_REVIEW,
        confidence=STATUS_WEIGHT[ValidationStatus.MANUAL_REVIEW],
        validator=VALIDATOR_NAME,
        method=VALIDATION_METHOD,
        evidence={
            **_context_evidence(finding),
            **(evidence or {}),
            "decision": "inconclusive",
            "reason": reason,
        },
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
    if normalized_type not in {"sql_injection", "sqli"}:
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
    if finding.parameter_location in {"json", "cookie", "header"}:
        if finding.parameter_location not in finding.http_request_context:
            return "insufficient_original_request_context"
    if session is None:
        return "missing_scoped_http_session"
    if not callable(getattr(session, "request", None)):
        return "scoped_http_session_missing_request_interface"
    return None


def _response_elapsed(response: Any, measured: float) -> float:
    explicit = getattr(response, "elapsed_seconds", None)
    if isinstance(explicit, Real) and not isinstance(explicit, bool):
        value = float(explicit)
        if math.isfinite(value) and value >= 0:
            return value
    elapsed = getattr(response, "elapsed", None)
    total_seconds = getattr(elapsed, "total_seconds", None)
    if callable(total_seconds):
        try:
            value = float(total_seconds())
            if math.isfinite(value) and value >= 0:
                return value
        except (TypeError, ValueError, RuntimeError):
            pass
    return measured


def _observe_response(
    response: Any,
    *,
    measured_seconds: float,
    attempts: int,
) -> _ResponseObservation:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", None)
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")
    return _ResponseObservation(
        status=status,
        text=text,
        elapsed_seconds=round(_response_elapsed(response, measured_seconds), 6),
        attempts=attempts,
    )


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
    if location == "header":
        return {"headers": original}
    raise ValueError("unsupported_parameter_location")


def _call_session(
    session: Any,
    *,
    method: str,
    url: str,
    kwargs: Dict[str, Any],
) -> Any:
    return session.request(
        method,
        url,
        timeout=_REQUEST_TIMEOUT_SECONDS,
        **kwargs,
    )


def _send_probe(
    finding: Finding,
    session: Any,
    *,
    url: str,
    value: str,
) -> _ResponseObservation:
    request_kwargs = _request_kwargs(finding, value)
    transient_errors = (httpx.TransportError, ConnectionError, TimeoutError)
    for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
        started = time.monotonic()
        try:
            response = _call_session(
                session,
                method=finding.http_method or "",
                url=url,
                kwargs=request_kwargs,
            )
            return _observe_response(
                response,
                measured_seconds=time.monotonic() - started,
                attempts=attempt,
            )
        except transient_errors as exc:
            if attempt >= _MAX_REQUEST_ATTEMPTS:
                raise _ProbeRequestFailure(attempt) from exc
            time.sleep(_RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))
        except Exception as exc:
            raise _ProbeRequestFailure(attempt) from exc
    raise _ProbeRequestFailure(_MAX_REQUEST_ATTEMPTS)


def _normalize_response_text(text: str) -> str:
    """Remove narrow dynamic tokens while preserving meaningful page content."""
    bounded = text[:_COMPARISON_CHARACTER_LIMIT]
    bounded = _DYNAMIC_INPUT_RE.sub(
        r"\g<prefix><dynamic>\g<suffix>", bounded,
    )
    bounded = _DYNAMIC_ATTRIBUTE_RE.sub(r"\g<prefix><dynamic>", bounded)
    bounded = _ISO_TIMESTAMP_RE.sub("<dynamic-timestamp>", bounded)
    bounded = _NAMED_TIMESTAMP_RE.sub(
        r"\g<prefix><dynamic-timestamp>", bounded,
    )
    bounded = _UUID_RE.sub("<dynamic-uuid>", bounded)
    return bounded


def _similarity(left: str, right: str) -> float:
    return SequenceMatcher(
        None,
        _normalize_response_text(left),
        _normalize_response_text(right),
    ).ratio()


def _waf_interference(observation: _ResponseObservation) -> bool:
    if observation.status in _WAF_STATUS_CODES:
        return True
    bounded = observation.text[:_COMPARISON_CHARACTER_LIMIT]
    return any(pattern.search(bounded) for pattern in _WAF_TEXT_PATTERNS)


def _observation_evidence(observation: _ResponseObservation) -> Dict[str, Any]:
    return {
        "http_status": observation.status,
        "response_length": len(observation.text),
        "elapsed_seconds": observation.elapsed_seconds,
        "attempts": observation.attempts,
    }


def _run_boolean_method(
    finding: Finding,
    session: Any,
    *,
    url: str,
) -> tuple[_MethodResult, Optional[_ResponseObservation]]:
    evidence: Dict[str, Any] = {
        "state": "error",
        "control_value": _CONTROL_VALUE,
        "confirming_pairs_required": _BOOLEAN_CONFIRMING_PAIRS_REQUIRED,
        "pairs": [],
    }
    try:
        baseline = _send_probe(
            finding, session, url=url, value=_CONTROL_VALUE,
        )
    except _ProbeRequestFailure as exc:
        evidence.update({
            "reason": "baseline_request_failed",
            "attempts": exc.attempts,
        })
        return _MethodResult("error", evidence), None

    evidence["baseline"] = _observation_evidence(baseline)
    if _waf_interference(baseline):
        evidence.update({
            "state": "inconclusive",
            "reason": "baseline_filter_interference",
        })
        return _MethodResult("inconclusive", evidence, True), baseline
    if not 200 <= baseline.status < 300:
        evidence.update({
            "state": "inconclusive",
            "reason": "non_success_baseline_status",
        })
        return _MethodResult("inconclusive", evidence), baseline

    confirming_pairs = 0
    rejected_pairs = 0
    for pair_index, (true_value, false_value) in enumerate(
        _BOOLEAN_PROBE_PAIRS,
        start=1,
    ):
        try:
            true_response = _send_probe(
                finding, session, url=url, value=true_value,
            )
            false_response = _send_probe(
                finding, session, url=url, value=false_value,
            )
        except _ProbeRequestFailure as exc:
            evidence.update({
                "state": "error",
                "reason": "boolean_pair_request_failed",
                "failed_pair_index": pair_index,
                "attempts": exc.attempts,
            })
            return _MethodResult("error", evidence), baseline

        pair_waf = (
            _waf_interference(true_response)
            or _waf_interference(false_response)
        )
        baseline_true = _similarity(baseline.text, true_response.text)
        baseline_false = _similarity(baseline.text, false_response.text)
        true_false = _similarity(true_response.text, false_response.text)
        similarity_delta = baseline_true - baseline_false
        statuses_consistent = (
            true_response.status == false_response.status == baseline.status
        )
        pair_confirmed = (
            statuses_consistent
            and baseline_true >= _CONFIRMED_BASELINE_TRUE_MIN
            and baseline_false <= _CONFIRMED_BASELINE_FALSE_MAX
            and similarity_delta >= _CONFIRMED_SIMILARITY_DELTA_MIN
            and true_false <= _CONFIRMED_TRUE_FALSE_MAX
            and not pair_waf
        )
        pair_rejected = (
            statuses_consistent
            and true_false >= _REJECTED_TRUE_FALSE_MIN
            and abs(similarity_delta) <= _REJECTED_DELTA_MAX
            and not pair_waf
        )
        confirming_pairs += int(pair_confirmed)
        rejected_pairs += int(pair_rejected)
        evidence["pairs"].append({
            "pair_index": pair_index,
            "true_probe": true_value,
            "false_probe": false_value,
            "true_http_status": true_response.status,
            "false_http_status": false_response.status,
            "true_response_length": len(true_response.text),
            "false_response_length": len(false_response.text),
            "true_attempts": true_response.attempts,
            "false_attempts": false_response.attempts,
            "baseline_true_similarity": round(baseline_true, 6),
            "baseline_false_similarity": round(baseline_false, 6),
            "true_false_similarity": round(true_false, 6),
            "similarity_delta": round(similarity_delta, 6),
            "pair_confirmed": pair_confirmed,
            "pair_rejected": pair_rejected,
            "waf_or_filter_interference": pair_waf,
        })
        if pair_waf:
            evidence.update({
                "state": "inconclusive",
                "reason": "probe_filter_interference",
                "confirming_pairs": confirming_pairs,
                "rejected_pairs": rejected_pairs,
            })
            return _MethodResult("inconclusive", evidence, True), baseline

    evidence.update({
        "confirming_pairs": confirming_pairs,
        "rejected_pairs": rejected_pairs,
        "total_pairs": len(_BOOLEAN_PROBE_PAIRS),
        "thresholds": {
            "baseline_true_min": _CONFIRMED_BASELINE_TRUE_MIN,
            "baseline_false_max": _CONFIRMED_BASELINE_FALSE_MAX,
            "similarity_delta_min": _CONFIRMED_SIMILARITY_DELTA_MIN,
            "true_false_max": _CONFIRMED_TRUE_FALSE_MAX,
        },
    })
    if confirming_pairs >= _BOOLEAN_CONFIRMING_PAIRS_REQUIRED:
        evidence.update({
            "state": "confirmed",
            "reason": "multiple_boolean_pairs_confirmed",
        })
        return _MethodResult("confirmed", evidence), baseline
    if rejected_pairs == len(_BOOLEAN_PROBE_PAIRS):
        evidence.update({
            "state": "negative",
            "reason": "all_boolean_pairs_equivalent",
        })
        return _MethodResult("negative", evidence), baseline
    evidence.update({
        "state": "inconclusive",
        "reason": "insufficient_confirming_boolean_pairs",
    })
    return _MethodResult("inconclusive", evidence), baseline


def _database_error_categories(text: str) -> list[str]:
    bounded = text[:_COMPARISON_CHARACTER_LIMIT]
    return sorted(
        category
        for category, signatures in _ERROR_SIGNATURES.items()
        if any(signature.search(bounded) for signature in signatures)
    )


def _run_error_method(
    finding: Finding,
    session: Any,
    *,
    url: str,
    baseline: Optional[_ResponseObservation],
) -> _MethodResult:
    evidence: Dict[str, Any] = {"state": "error", "probes": []}
    if baseline is None:
        try:
            baseline = _send_probe(
                finding, session, url=url, value=_CONTROL_VALUE,
            )
        except _ProbeRequestFailure as exc:
            evidence.update({
                "reason": "baseline_request_failed",
                "attempts": exc.attempts,
            })
            return _MethodResult("error", evidence)

    baseline_categories = _database_error_categories(baseline.text)
    evidence.update({
        "baseline": _observation_evidence(baseline),
        "baseline_error_categories": baseline_categories,
    })
    if _waf_interference(baseline):
        evidence.update({
            "state": "inconclusive",
            "reason": "baseline_filter_interference",
        })
        return _MethodResult("inconclusive", evidence, True)

    introduced_categories: set[str] = set()
    for probe_index, (probe_name, probe_value) in enumerate(
        _ERROR_PROBES,
        start=1,
    ):
        try:
            response = _send_probe(
                finding, session, url=url, value=probe_value,
            )
        except _ProbeRequestFailure as exc:
            evidence.update({
                "state": "error",
                "reason": "error_probe_request_failed",
                "failed_probe_index": probe_index,
                "attempts": exc.attempts,
            })
            return _MethodResult("error", evidence)
        probe_waf = _waf_interference(response)
        categories = _database_error_categories(response.text)
        new_categories = sorted(set(categories) - set(baseline_categories))
        introduced_categories.update(new_categories)
        evidence["probes"].append({
            "probe_index": probe_index,
            "probe_name": probe_name,
            "probe_value": probe_value,
            "http_status": response.status,
            "response_length": len(response.text),
            "attempts": response.attempts,
            "matched_error_categories": categories,
            "new_error_categories": new_categories,
            "new_relative_to_baseline": bool(new_categories),
            "waf_or_filter_interference": probe_waf,
        })
        if probe_waf:
            evidence.update({
                "state": "inconclusive",
                "reason": "probe_filter_interference",
            })
            return _MethodResult("inconclusive", evidence, True)

    evidence["introduced_error_categories"] = sorted(introduced_categories)
    if introduced_categories:
        evidence.update({
            "state": "confirmed",
            "reason": "new_database_error_signature",
        })
        return _MethodResult("confirmed", evidence)
    evidence.update({
        "state": "negative",
        "reason": "no_new_database_error_signature",
    })
    return _MethodResult("negative", evidence)


def _run_timing_method(
    finding: Finding,
    session: Any,
    *,
    url: str,
) -> _MethodResult:
    maximum_requests = (
        _TIMING_BASELINE_SAMPLES
        + len(_TIMING_PROBES) * _TIMING_REPETITIONS
    )
    evidence: Dict[str, Any] = {
        "state": "error",
        "expected_delay_seconds": _CONTROLLED_DELAY_SECONDS,
        "baseline_samples": [],
        "probes": [],
        "maximum_timing_requests": maximum_requests,
    }
    baselines = []
    for sample_index in range(1, _TIMING_BASELINE_SAMPLES + 1):
        try:
            response = _send_probe(
                finding, session, url=url, value=_CONTROL_VALUE,
            )
        except _ProbeRequestFailure as exc:
            evidence.update({
                "state": "error",
                "reason": "timing_baseline_request_failed",
                "failed_sample_index": sample_index,
                "attempts": exc.attempts,
            })
            return _MethodResult("error", evidence)
        if _waf_interference(response):
            evidence.update({
                "state": "inconclusive",
                "reason": "baseline_filter_interference",
            })
            return _MethodResult("inconclusive", evidence, True)
        if not 200 <= response.status < 300:
            evidence.update({
                "state": "inconclusive",
                "reason": "non_success_baseline_status",
            })
            return _MethodResult("inconclusive", evidence)
        baselines.append(response.elapsed_seconds)
        evidence["baseline_samples"].append({
            "sample_index": sample_index,
            **_observation_evidence(response),
        })

    baseline_mean = sum(baselines) / len(baselines)
    baseline_jitter = max(baselines) - min(baselines)
    evidence.update({
        "baseline_mean_seconds": round(baseline_mean, 6),
        "baseline_jitter_seconds": round(baseline_jitter, 6),
    })
    if (
        baseline_mean > _TIMING_BASELINE_MAX_SECONDS
        or baseline_jitter > _TIMING_BASELINE_JITTER_MAX_SECONDS
    ):
        evidence.update({
            "state": "inconclusive",
            "reason": "slow_or_unstable_baseline",
        })
        return _MethodResult("inconclusive", evidence)

    confirmation_threshold = baseline_mean + (
        _CONTROLLED_DELAY_SECONDS * _TIMING_CONFIRMATION_FRACTION
    )
    evidence["confirmation_threshold_seconds"] = round(
        confirmation_threshold,
        6,
    )
    inconsistent_timing = False
    for engine, probe_value in _TIMING_PROBES:
        observations = []
        for repetition in range(1, _TIMING_REPETITIONS + 1):
            try:
                response = _send_probe(
                    finding, session, url=url, value=probe_value,
                )
            except _ProbeRequestFailure as exc:
                evidence.update({
                    "state": "error",
                    "reason": "timing_probe_request_failed",
                    "failed_engine": engine,
                    "failed_repetition": repetition,
                    "attempts": exc.attempts,
                })
                return _MethodResult("error", evidence)
            if _waf_interference(response):
                evidence.update({
                    "state": "inconclusive",
                    "reason": "probe_filter_interference",
                })
                return _MethodResult("inconclusive", evidence, True)
            if not 200 <= response.status < 300:
                evidence.update({
                    "state": "inconclusive",
                    "reason": "non_success_timing_status",
                })
                return _MethodResult("inconclusive", evidence)
            observations.append(response)

        delayed = [
            item.elapsed_seconds >= confirmation_threshold
            for item in observations
        ]
        evidence["probes"].append({
            "engine": engine,
            "probe_value": probe_value,
            "observations": [
                {
                    "repetition": index,
                    **_observation_evidence(item),
                }
                for index, item in enumerate(observations, start=1)
            ],
            "delayed_observations": sum(delayed),
            "repeatable_delay": all(delayed),
        })
        if all(delayed):
            evidence.update({
                "state": "confirmed",
                "reason": "repeatable_controlled_delay_observed",
                "confirmed_engine": engine,
            })
            return _MethodResult("confirmed", evidence)
        if any(delayed):
            inconsistent_timing = True

    if inconsistent_timing:
        evidence.update({
            "state": "inconclusive",
            "reason": "non_repeatable_timing_signal",
        })
        return _MethodResult("inconclusive", evidence)
    evidence.update({
        "state": "negative",
        "reason": "no_controlled_delay_observed",
    })
    return _MethodResult("negative", evidence)


def _final_evidence(
    finding: Finding,
    results: Mapping[str, _MethodResult],
    *,
    decision: str,
    reason: str,
) -> Dict[str, Any]:
    triggered = [
        name for name, result in results.items()
        if result.state == "confirmed"
    ]
    return {
        **_context_evidence(finding),
        "request_timeout_seconds": _REQUEST_TIMEOUT_SECONDS,
        "maximum_request_attempts": _MAX_REQUEST_ATTEMPTS,
        "waf_or_filter_interference": any(
            result.waf_or_filter_interference for result in results.values()
        ),
        "methods_triggered": triggered,
        "detection_methods": {
            name: result.evidence for name, result in results.items()
        },
        "decision": decision,
        "reason": reason,
    }


def _confirmed_confidence(triggered_methods: Sequence[str]) -> float:
    strongest = max(
        _METHOD_CONFIDENCE[method] for method in triggered_methods
    )
    bonus = _CORROBORATION_BONUS * max(0, len(triggered_methods) - 1)
    return min(0.99, round(strongest + bonus, 2))


def validate_generic_http_sqli(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Aggregate bounded boolean, error, and timing SQLi evidence."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    boolean_result, baseline = _run_boolean_method(
        finding, session, url=url,
    )
    results: Dict[str, _MethodResult] = {
        "boolean-response-differential": boolean_result,
    }
    if boolean_result.waf_or_filter_interference:
        results["error-based"] = _MethodResult(
            "skipped",
            {"state": "skipped", "reason": "filter_interference_detected"},
        )
    else:
        results["error-based"] = _run_error_method(
            finding,
            session,
            url=url,
            baseline=baseline,
        )

    if any(
        result.waf_or_filter_interference for result in results.values()
    ):
        results["time-based-blind"] = _MethodResult(
            "skipped",
            {"state": "skipped", "reason": "filter_interference_detected"},
        )
    elif any(result.state == "confirmed" for result in results.values()):
        results["time-based-blind"] = _MethodResult(
            "skipped",
            {
                "state": "skipped",
                "reason": "strong_non_timing_method_confirmed",
                "expected_delay_seconds": _CONTROLLED_DELAY_SECONDS,
                "maximum_timing_requests": 0,
            },
        )
    else:
        results["time-based-blind"] = _run_timing_method(
            finding, session, url=url,
        )

    real_tool = sqlmap_confirmation(finding)

    if any(
        result.waf_or_filter_interference for result in results.values()
    ):
        evidence = _final_evidence(
            finding,
            results,
            decision="inconclusive",
            reason="waf_or_filter_interference",
        )
        evidence["real_tool"] = _real_tool_summary(real_tool)
        return _manual_review(
            finding,
            "waf_or_filter_interference",
            evidence=evidence,
        )

    triggered_methods = [
        name for name, result in results.items()
        if result.state == "confirmed"
    ]

    # Genuine external tool confirmation takes priority.
    if real_tool.usable and real_tool.confirmed:
        evidence = _final_evidence(
            finding,
            results,
            decision="confirmed",
            reason="real_tool_sqlmap_confirmation",
        )
        evidence["real_tool"] = _real_tool_summary(real_tool)
        heuristic_conf = (
            _confirmed_confidence(triggered_methods)
            if triggered_methods
            else 0.0
        )
        confidence = min(0.99, max(0.95, heuristic_conf))
        return ValidationResult(
            status=ValidationStatus.CONFIRMED,
            confidence=confidence,
            validator=VALIDATOR_NAME,
            method=f"{VALIDATION_METHOD} + sqlmap",
            evidence=evidence,
        )

    # Real tool ran clean negative — reconcile with the heuristics.
    if real_tool.usable and real_tool.not_vulnerable:
        if triggered_methods:
            evidence = _final_evidence(
                finding,
                results,
                decision="inconclusive",
                reason="real_tool_conflict_requires_human_review",
            )
            evidence["real_tool"] = _real_tool_summary(real_tool)
            return _manual_review(
                finding,
                "real_tool_conflict_requires_human_review",
                evidence=evidence,
            )
        all_negative = all(
            result.state in {"negative", "error"}
            for result in results.values()
        )
        if all_negative:
            evidence = _final_evidence(
                finding,
                results,
                decision="rejected",
                reason="heuristics_and_real_tool_negative",
            )
            evidence["real_tool"] = _real_tool_summary(real_tool)
            return ValidationResult(
                status=ValidationStatus.REJECTED,
                confidence=0.88,
                validator=VALIDATOR_NAME,
                method=f"{VALIDATION_METHOD} + sqlmap",
                evidence=evidence,
            )

    # Real tool timed out or produced an error — the heuristic path below
    # remains authoritative; the real_tool evidence stays for auditability.

    if triggered_methods:
        evidence = _final_evidence(
            finding,
            results,
            decision="confirmed",
            reason="one_or_more_detection_methods_confirmed",
        )
        evidence["real_tool"] = _real_tool_summary(real_tool)
        return ValidationResult(
            status=ValidationStatus.CONFIRMED,
            confidence=_confirmed_confidence(triggered_methods),
            validator=VALIDATOR_NAME,
            method=VALIDATION_METHOD,
            evidence=evidence,
        )

    states = [result.state for result in results.values()]
    if all(state == "negative" for state in states):
        evidence = _final_evidence(
            finding,
            results,
            decision="rejected",
            reason="all_detection_methods_negative",
        )
        evidence["real_tool"] = _real_tool_summary(real_tool)
        return ValidationResult(
            status=ValidationStatus.REJECTED,
            confidence=0.9,
            validator=VALIDATOR_NAME,
            method=VALIDATION_METHOD,
            evidence=evidence,
        )

    evidence = _final_evidence(
        finding,
        results,
        decision="inconclusive",
        reason="incomplete_or_ambiguous_detection_coverage",
    )
    evidence["real_tool"] = _real_tool_summary(real_tool)
    return _manual_review(
        finding,
        "incomplete_or_ambiguous_detection_coverage",
        evidence=evidence,
        error=(
            "One or more bounded SQLi detection methods did not complete"
            if "error" in states
            else None
        ),
    )


def fixed_probe_values() -> tuple[str, ...]:
    """Return the fixed probes for safe presentation and security tests."""
    boolean_values = tuple(
        value for pair in _BOOLEAN_PROBE_PAIRS for value in pair
    )
    return (
        _CONTROL_VALUE,
        *boolean_values,
        *(value for _, value in _ERROR_PROBES),
        *(value for _, value in _TIMING_PROBES),
    )
