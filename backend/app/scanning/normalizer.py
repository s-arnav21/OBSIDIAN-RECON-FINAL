"""Pure normalization from trusted HTTP scanner records to Findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from app.models.finding import Finding, ValidationStatus
from app.scanning.models import ScannerCandidateRecord


GENERIC_SQLI_VALIDATOR_ID = "generic-http-sqli"
GENERIC_REFLECTED_XSS_VALIDATOR_ID = "generic-http-reflected-xss"
GENERIC_SSRF_VALIDATOR_ID = "generic-http-ssrf"
GENERIC_EXPOSED_RESOURCE_VALIDATOR_ID = "generic-http-exposed-resource"
GENERIC_COMMAND_EXECUTION_VALIDATOR_ID = "generic-http-command-execution"
CONTROLLED_SYSTEM_INFORMATION_VALIDATOR_ID = (
    "controlled-http-system-information-discovery"
)
RECON_MANUAL_REVIEW_VALIDATOR_ID = "recon-manual-review"
REFLECTED_XSS_REQUEST_SHAPES = frozenset(
    (method, location)
    for method in ("GET", "POST", "PUT", "PATCH")
    for location in ("query", "form", "json", "cookie", "header")
)
SSRF_REQUEST_SHAPES = frozenset(
    (method, location)
    for method in ("GET", "POST", "PUT", "PATCH")
    for location in ("query", "form", "json", "cookie", "header")
)
SQLI_REQUEST_SHAPES = frozenset(
    (method, location)
    for method in ("GET", "POST", "PUT", "PATCH")
    for location in ("query", "form", "json", "cookie", "header")
)
SQLI_TYPES = frozenset({"sql_injection", "sqli"})
COMMAND_EXECUTION_TYPES = frozenset({
    "command_execution",
    "unix_shell_command_execution",
})
SYSTEM_INFORMATION_DISCOVERY_TYPES = frozenset({
    "system_information_discovery",
})
REFLECTED_XSS_TYPES = frozenset({
    "cross_site_scripting",
    "reflected_cross_site_scripting",
    "reflected_xss",
    "xss",
})
SSRF_TYPES = frozenset({"server_side_request_forgery", "ssrf"})
EXPOSURE_TYPE_MAP = {
    "configuration_exposure": "sensitive_data_exposure",
    "exposed_resource": "sensitive_data_exposure",
    "sensitive_data_exposure": "sensitive_data_exposure",
    "sensitive_resource_exposure": "sensitive_data_exposure",
    "debug_resource_exposure": "information_disclosure",
    "directory_resource_disclosure": "information_disclosure",
    "information_disclosure": "information_disclosure",
}


class ScannerNormalizationError(ValueError):
    """Raised when an internal scanner record cannot be safely normalized."""


@dataclass(frozen=True)
class HttpScannerRecord:
    """A trusted internal observation about one HTTP candidate parameter."""

    record_id: str
    scan_id: str
    asset_id: str
    target: str
    endpoint: str
    http_method: str
    parameter_name: str
    parameter_location: str
    scanner_name: str
    scanner_template_id: str
    vulnerability_type: str
    severity: str = "medium"
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    # Ephemeral trusted request state. Never included in Finding.to_dict().
    http_request_context: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass(frozen=True)
class ExposedResourceScannerRecord:
    """A trusted internal observation about one discovered resource path."""

    record_id: str
    scan_id: str
    asset_id: str
    target: str
    endpoint: str
    scanner_name: str
    scanner_template_id: str
    vulnerability_type: str
    severity: str = "medium"
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass(frozen=True)
class _NormalizedTarget:
    origin: str
    host: str
    port: int
    protocol: str


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScannerNormalizationError(
            f"{field_name} must be a non-empty string"
        )
    return value.strip()


def _normalize_target(target: Any) -> _NormalizedTarget:
    value = _required_text(target, "target")
    try:
        parsed = urlsplit(value)
        explicit_port = parsed.port
    except ValueError as exc:
        raise ScannerNormalizationError("target contains an invalid port") from exc

    protocol = parsed.scheme.lower()
    if protocol not in {"http", "https"}:
        raise ScannerNormalizationError("target must use http or https")
    if not parsed.hostname:
        raise ScannerNormalizationError("target must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ScannerNormalizationError("target must not include credentials")
    if parsed.query or parsed.fragment:
        raise ScannerNormalizationError(
            "target must not include a query string or fragment"
        )
    if parsed.path not in {"", "/"}:
        raise ScannerNormalizationError(
            "target must be an origin; provide the path as endpoint"
        )

    host = parsed.hostname.lower()
    port = explicit_port or (443 if protocol == "https" else 80)
    default_port = 443 if protocol == "https" else 80
    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host if port == default_port else f"{display_host}:{port}"
    origin = urlunsplit((protocol, netloc, "", "", ""))
    return _NormalizedTarget(
        origin=origin,
        host=host,
        port=port,
        protocol=protocol,
    )


def _normalize_endpoint(endpoint: Any) -> str:
    value = _required_text(endpoint, "endpoint")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        raise ScannerNormalizationError(
            "endpoint must be a relative path on the approved target origin"
        )
    if parsed.query or parsed.fragment:
        raise ScannerNormalizationError(
            "endpoint must not include a query string or fragment"
        )
    if not parsed.path.startswith("/"):
        raise ScannerNormalizationError("endpoint must start with /")
    return parsed.path


def _normalized_type_name(value: Any) -> str:
    normalized = _required_text(value, "vulnerability_type")
    return normalized.lower().replace("-", "_").replace(" ", "_")


def _validate_evidence(record: Any) -> tuple[Dict[str, Any], List[str]]:
    evidence = record.evidence
    if not isinstance(evidence, dict):
        raise ScannerNormalizationError("evidence must be a dictionary")
    evidence_refs = record.evidence_refs
    if not isinstance(evidence_refs, list) or not all(
        isinstance(reference, str) and reference
        for reference in evidence_refs
    ):
        raise ScannerNormalizationError(
            "evidence_refs must be a list of non-empty strings"
        )
    return dict(evidence), list(evidence_refs)


def _build_finding(
    record: Any,
    *,
    vulnerability_type: str,
    validator_id: str,
    http_method: Optional[str],
    parameter_name: Optional[str],
    parameter_location: Optional[str],
) -> Finding:
    target = _normalize_target(record.target)
    endpoint = _normalize_endpoint(record.endpoint)
    evidence, evidence_refs = _validate_evidence(record)

    return Finding(
        finding_id=_required_text(record.record_id, "record_id"),
        scan_id=_required_text(record.scan_id, "scan_id"),
        asset_id=_required_text(record.asset_id, "asset_id"),
        target=target.origin,
        host=target.host,
        port=target.port,
        protocol=target.protocol,
        endpoint=endpoint,
        source=_required_text(record.scanner_name, "scanner_name"),
        template_id=_required_text(
            record.scanner_template_id,
            "scanner_template_id",
        ),
        vulnerability_type=vulnerability_type,
        severity=_required_text(record.severity, "severity").lower(),
        validation_status=ValidationStatus.DETECTED,
        validation_confidence=0.2,
        evidence=evidence,
        evidence_refs=evidence_refs,
        observed_at=_required_text(record.observed_at, "observed_at"),
        raw_finding_ref=_required_text(record.record_id, "record_id"),
        validator_id=validator_id,
        http_method=http_method,
        parameter_name=parameter_name,
        parameter_location=parameter_location,
        http_request_context=getattr(record, "http_request_context", {}),
    )


def _normalize_parameterized_record(
    record: HttpScannerRecord,
    *,
    vulnerability_type: str,
    validator_id: str,
    request_shape_error: str,
    supported_request_shapes: frozenset[tuple[str, str]],
) -> Finding:
    http_method = _required_text(record.http_method, "http_method").upper()
    parameter_name = _required_text(record.parameter_name, "parameter_name")
    parameter_location = _required_text(
        record.parameter_location,
        "parameter_location",
    ).lower()

    if (http_method, parameter_location) not in supported_request_shapes:
        raise ScannerNormalizationError(request_shape_error)

    return _build_finding(
        record,
        vulnerability_type=vulnerability_type,
        validator_id=validator_id,
        http_method=http_method,
        parameter_name=parameter_name,
        parameter_location=parameter_location,
    )


def normalize_http_sqli_record(record: HttpScannerRecord) -> Finding:
    """Convert one trusted scanner observation into a canonical SQLi Finding."""
    if not isinstance(record, HttpScannerRecord):
        raise TypeError("record must be an HttpScannerRecord")

    normalized_type = _normalized_type_name(record.vulnerability_type)
    if normalized_type not in SQLI_TYPES:
        raise ScannerNormalizationError(
            "vulnerability_type must identify SQL injection"
        )
    return _normalize_parameterized_record(
        record,
        vulnerability_type="sql_injection",
        validator_id=GENERIC_SQLI_VALIDATOR_ID,
        request_shape_error=(
            "unsupported HTTP SQLi request shape"
        ),
        supported_request_shapes=SQLI_REQUEST_SHAPES,
    )


def normalize_reflected_xss_record(record: HttpScannerRecord) -> Finding:
    """Convert one trusted scanner observation into a reflected-XSS Finding."""
    if not isinstance(record, HttpScannerRecord):
        raise TypeError("record must be an HttpScannerRecord")

    normalized_type = _normalized_type_name(record.vulnerability_type)
    if normalized_type not in REFLECTED_XSS_TYPES:
        raise ScannerNormalizationError(
            "vulnerability_type must identify reflected XSS"
        )
    return _normalize_parameterized_record(
        record,
        vulnerability_type="reflected_xss",
        validator_id=GENERIC_REFLECTED_XSS_VALIDATOR_ID,
        request_shape_error="unsupported reflected-XSS request shape",
        supported_request_shapes=REFLECTED_XSS_REQUEST_SHAPES,
    )


def normalize_ssrf_record(record: HttpScannerRecord) -> Finding:
    """Convert one trusted scanner observation into a canonical SSRF Finding."""
    if not isinstance(record, HttpScannerRecord):
        raise TypeError("record must be an HttpScannerRecord")

    normalized_type = _normalized_type_name(record.vulnerability_type)
    if normalized_type not in SSRF_TYPES:
        raise ScannerNormalizationError(
            "vulnerability_type must identify server-side request forgery"
        )
    return _normalize_parameterized_record(
        record,
        vulnerability_type="ssrf",
        validator_id=GENERIC_SSRF_VALIDATOR_ID,
        request_shape_error="unsupported SSRF request shape",
        supported_request_shapes=SSRF_REQUEST_SHAPES,
    )


def normalize_command_execution_record(record: HttpScannerRecord) -> Finding:
    """Normalize a trusted synthetic command-execution sink observation."""
    if not isinstance(record, HttpScannerRecord):
        raise TypeError("record must be an HttpScannerRecord")

    normalized_type = _normalized_type_name(record.vulnerability_type)
    if normalized_type not in COMMAND_EXECUTION_TYPES:
        raise ScannerNormalizationError(
            "vulnerability_type must identify command execution"
        )

    http_method = _required_text(record.http_method, "http_method").upper()
    parameter_location = _required_text(
        record.parameter_location,
        "parameter_location",
    ).lower()
    if (http_method, parameter_location) != ("POST", "form"):
        raise ScannerNormalizationError(
            "controlled command-execution validation requires POST/form"
        )

    return _build_finding(
        record,
        vulnerability_type="command_execution",
        validator_id=GENERIC_COMMAND_EXECUTION_VALIDATOR_ID,
        http_method=http_method,
        parameter_name=_required_text(
            record.parameter_name,
            "parameter_name",
        ),
        parameter_location=parameter_location,
    )


def normalize_system_information_discovery_record(
    record: HttpScannerRecord,
) -> Finding:
    """Normalize the controlled fixture's synthetic discovery observation."""
    if not isinstance(record, HttpScannerRecord):
        raise TypeError("record must be an HttpScannerRecord")

    normalized_type = _normalized_type_name(record.vulnerability_type)
    if normalized_type not in SYSTEM_INFORMATION_DISCOVERY_TYPES:
        raise ScannerNormalizationError(
            "vulnerability_type must identify system information discovery"
        )

    http_method = _required_text(record.http_method, "http_method").upper()
    parameter_location = _required_text(
        record.parameter_location,
        "parameter_location",
    ).lower()
    if (http_method, parameter_location) != ("POST", "form"):
        raise ScannerNormalizationError(
            "controlled system-information validation requires POST/form"
        )

    return _build_finding(
        record,
        vulnerability_type="system_information_discovery",
        validator_id=CONTROLLED_SYSTEM_INFORMATION_VALIDATOR_ID,
        http_method=http_method,
        parameter_name=_required_text(
            record.parameter_name,
            "parameter_name",
        ),
        parameter_location=parameter_location,
    )


def normalize_exposed_resource_record(
    record: ExposedResourceScannerRecord,
) -> Finding:
    """Convert one trusted resource observation into an exposure Finding."""
    if not isinstance(record, ExposedResourceScannerRecord):
        raise TypeError("record must be an ExposedResourceScannerRecord")

    normalized_type = _normalized_type_name(record.vulnerability_type)
    vulnerability_type = EXPOSURE_TYPE_MAP.get(normalized_type)
    if vulnerability_type is None:
        raise ScannerNormalizationError(
            "vulnerability_type must identify an exposed resource"
        )
    return _build_finding(
        record,
        vulnerability_type=vulnerability_type,
        validator_id=GENERIC_EXPOSED_RESOURCE_VALIDATOR_ID,
        http_method="GET",
        parameter_name=None,
        parameter_location=None,
    )


def _candidate_finding(
    record: ScannerCandidateRecord,
    *,
    vulnerability_type: str,
    validator_id: Optional[str] = None,
    http_method: Optional[str] = None,
    parameter_name: Optional[str] = None,
    parameter_location: Optional[str] = None,
) -> Finding:
    """Preserve a candidate even when validation context is incomplete."""
    target = _normalize_target(record.target)
    endpoint = (
        _normalize_endpoint(record.endpoint)
        if record.endpoint is not None
        else None
    )
    evidence, evidence_refs = _validate_evidence(record)
    observed_at = record.observed_at or datetime.now(timezone.utc).isoformat()
    return Finding(
        finding_id=_required_text(record.record_id, "record_id"),
        scan_id=_required_text(record.scan_id, "scan_id"),
        asset_id=_required_text(record.asset_id, "asset_id"),
        target=target.origin,
        host=target.host,
        port=target.port,
        protocol=target.protocol,
        endpoint=endpoint,
        source=_required_text(record.scanner_name, "scanner_name"),
        template_id=_required_text(
            record.scanner_template_id,
            "scanner_template_id",
        ),
        vulnerability_type=vulnerability_type,
        severity=_required_text(record.severity, "severity").lower(),
        validation_status=ValidationStatus.DETECTED,
        validation_confidence=0.2,
        evidence=evidence,
        evidence_refs=evidence_refs,
        observed_at=observed_at,
        raw_finding_ref=record.record_id,
        validator_id=validator_id,
        http_method=http_method,
        parameter_name=parameter_name,
        parameter_location=parameter_location,
        http_request_context=getattr(record, "http_request_context", {}),
    )


def normalize_scanner_candidate(record: ScannerCandidateRecord) -> Finding:
    """Normalize a real scanner candidate without guessing missing context.

    A registered validator is selected only when the scanner explicitly supplies
    every field required by that validator. Command-execution candidates remain
    manual-review-only outside the controlled synthetic fixture.
    """
    if not isinstance(record, ScannerCandidateRecord):
        raise TypeError("record must be a ScannerCandidateRecord")
    normalized_type = _normalized_type_name(record.vulnerability_type)
    method = record.http_method.strip().upper() if record.http_method else None
    location = (
        record.parameter_location.strip().lower()
        if record.parameter_location
        else None
    )
    parameter = record.parameter_name.strip() if record.parameter_name else None
    complete_parameter_context = bool(
        record.endpoint
        and method
        and location
        and parameter
        and (
            (method, location) in SQLI_REQUEST_SHAPES
            if normalized_type in SQLI_TYPES
            else (method, location) in SSRF_REQUEST_SHAPES
            if normalized_type in SSRF_TYPES
            else (method, location) in REFLECTED_XSS_REQUEST_SHAPES
        )
    )

    validator_id: Optional[str] = RECON_MANUAL_REVIEW_VALIDATOR_ID
    canonical_type = normalized_type
    if normalized_type in SQLI_TYPES:
        canonical_type = "sql_injection"
        if complete_parameter_context:
            validator_id = GENERIC_SQLI_VALIDATOR_ID
    elif normalized_type in REFLECTED_XSS_TYPES:
        canonical_type = "reflected_xss"
        if complete_parameter_context:
            validator_id = GENERIC_REFLECTED_XSS_VALIDATOR_ID
    elif normalized_type in SSRF_TYPES:
        canonical_type = "ssrf"
        if complete_parameter_context:
            validator_id = GENERIC_SSRF_VALIDATOR_ID
    elif normalized_type in EXPOSURE_TYPE_MAP:
        canonical_type = EXPOSURE_TYPE_MAP[normalized_type]
        if record.endpoint:
            validator_id = GENERIC_EXPOSED_RESOURCE_VALIDATOR_ID
            method = "GET"
            location = None
            parameter = None
    elif normalized_type in COMMAND_EXECUTION_TYPES:
        canonical_type = "command_execution"
        # Deliberately manual review: active command execution is fixture-only.

    return _candidate_finding(
        record,
        vulnerability_type=canonical_type,
        validator_id=validator_id,
        http_method=method,
        parameter_name=parameter,
        parameter_location=location,
    )
