"""Canonical finding contract for Obsidian Recon."""

from __future__ import annotations

import math
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from numbers import Real
from typing import Any, Dict, List, Optional


class ValidationStatus:
    """Supported validation states shared across findings and validators."""

    REJECTED = "rejected"
    DETECTED = "detected"
    LIKELY = "likely"
    MANUAL_REVIEW = "manual_review"
    CONFIRMED = "confirmed"
    ERROR = "error"

    SUPPORTED = frozenset({
        REJECTED,
        DETECTED,
        LIKELY,
        MANUAL_REVIEW,
        CONFIRMED,
        ERROR,
    })
    ALIASES = {
        "not_exploitable": REJECTED,
    }

    @classmethod
    def normalize(cls, status: str) -> str:
        if not isinstance(status, str) or not status.strip():
            raise ValueError("validation status must be a non-empty string")

        normalized = status.strip().lower()
        normalized = cls.ALIASES.get(normalized, normalized)
        if normalized not in cls.SUPPORTED:
            supported = ", ".join(sorted(cls.SUPPORTED))
            raise ValueError(
                f"unsupported validation status {status!r}; expected one of: {supported}"
            )
        return normalized


class ParameterLocation:
    """Supported locations for an HTTP request parameter."""

    QUERY = "query"
    FORM = "form"
    JSON = "json"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"

    SUPPORTED = frozenset({QUERY, FORM, JSON, PATH, HEADER, COOKIE})

    @classmethod
    def normalize(cls, location: str) -> str:
        if not isinstance(location, str) or not location.strip():
            raise ValueError("parameter_location must be a non-empty string")

        normalized = location.strip().lower()
        if normalized not in cls.SUPPORTED:
            supported = ", ".join(sorted(cls.SUPPORTED))
            raise ValueError(
                f"unsupported parameter_location {location!r}; "
                f"expected one of: {supported}"
            )
        return normalized


STATUS_WEIGHT: Dict[str, float] = {
    ValidationStatus.REJECTED: 0.0,
    ValidationStatus.DETECTED: 0.2,
    ValidationStatus.LIKELY: 0.5,
    ValidationStatus.MANUAL_REVIEW: 0.6,
    ValidationStatus.CONFIRMED: 1.0,
    ValidationStatus.ERROR: 0.0,
}


def validate_confidence(value: Real, field_name: str = "confidence") -> float:
    """Return a numeric confidence value after enforcing the 0.0–1.0 range."""
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{field_name} must be numeric")

    confidence = float(value)
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        raise ValueError(f"{field_name} must be between 0.0 and 1.0")
    return confidence


def _require_non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


@dataclass
class Finding:
    """A normalized security finding passed between backend pipeline stages."""

    # Required identity and assessment context.
    finding_id: str
    scan_id: str
    asset_id: str
    target: str
    host: str
    source: str
    vulnerability_type: str

    # Network/application location.
    port: Optional[int] = None
    protocol: Optional[str] = None
    endpoint: Optional[str] = None

    # Scanner and vulnerability metadata.
    template_id: Optional[str] = None
    severity: str = "medium"

    # Validation state.
    validation_status: str = ValidationStatus.DETECTED
    validation_confidence: float = 0.0

    # Evidence.
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)

    # Observation timestamp.
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Existing classification and attack-chain fields retained for compatibility.
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    requires_all: List[str] = field(default_factory=list)
    requires_any: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    raw_finding_ref: Optional[str] = None

    # Optional validation routing and HTTP request context.
    validator_id: Optional[str] = None
    http_method: Optional[str] = None
    parameter_name: Optional[str] = None
    parameter_location: Optional[str] = None

    # Ephemeral original request state used by validators. It is intentionally
    # excluded from to_dict() so headers/cookies cannot enter API or persistence
    # output through the canonical Finding serializer.
    http_request_context: Dict[str, Dict[str, Any]] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        for field_name in (
            "finding_id",
            "scan_id",
            "asset_id",
            "target",
            "host",
            "source",
            "vulnerability_type",
        ):
            _require_non_empty_string(getattr(self, field_name), field_name)

        if self.port is not None:
            if isinstance(self.port, bool) or not isinstance(self.port, int):
                raise TypeError("port must be an integer or None")
            if not 1 <= self.port <= 65535:
                raise ValueError("port must be between 1 and 65535")

        for field_name in (
            "protocol",
            "endpoint",
            "http_method",
            "parameter_name",
            "parameter_location",
            "template_id",
            "validator_id",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string or None")

        if self.http_method is not None:
            self.http_method = _require_non_empty_string(
                self.http_method,
                "http_method",
            ).strip().upper()

        if self.parameter_location is not None:
            self.parameter_location = ParameterLocation.normalize(
                self.parameter_location
            )

        if not isinstance(self.http_request_context, dict):
            raise TypeError("http_request_context must be a dictionary")
        normalized_context: Dict[str, Dict[str, Any]] = {}
        for location, values in self.http_request_context.items():
            normalized_location = ParameterLocation.normalize(location)
            if normalized_location == ParameterLocation.PATH:
                raise ValueError(
                    "http_request_context does not support path parameters"
                )
            if not isinstance(values, dict):
                raise TypeError(
                    "http_request_context values must be dictionaries"
                )
            if not all(isinstance(name, str) and name for name in values):
                raise TypeError(
                    "http_request_context parameter names must be non-empty strings"
                )
            normalized_context[normalized_location] = deepcopy(values)
        self.http_request_context = normalized_context

        _require_non_empty_string(self.severity, "severity")
        _require_non_empty_string(self.observed_at, "observed_at")

        self.validation_status = ValidationStatus.normalize(self.validation_status)
        self.validation_confidence = validate_confidence(
            self.validation_confidence,
            "validation_confidence",
        )

        if not isinstance(self.evidence, dict):
            raise TypeError("evidence must be a dictionary")
        if not isinstance(self.evidence_refs, list) or not all(
            isinstance(ref, str) and ref for ref in self.evidence_refs
        ):
            raise TypeError("evidence_refs must be a list of non-empty strings")

        for field_name in (
            "requires_all",
            "requires_any",
            "requires",
            "provides",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, list) or not all(
                isinstance(capability, str) and capability
                for capability in value
            ):
                raise TypeError(
                    f"{field_name} must be a list of non-empty strings"
                )

    @property
    def status_weight(self) -> float:
        return STATUS_WEIGHT[self.validation_status]

    @property
    def is_usable(self) -> bool:
        return self.validation_status != ValidationStatus.REJECTED

    @property
    def is_confirmed(self) -> bool:
        return self.validation_status == ValidationStatus.CONFIRMED

    @property
    def affected_endpoint(self) -> Optional[str]:
        """Compatibility alias for the previous model field."""
        return self.endpoint

    @property
    def timestamp(self) -> str:
        """Compatibility alias for the previous model field."""
        return self.observed_at

    @property
    def effective_requires_all(self) -> List[str]:
        """Capabilities that must all be available before this finding."""
        return list(self.requires_all)

    @property
    def effective_requires_any(self) -> List[str]:
        """
        Capabilities where at least one must be available.

        Legacy requires is interpreted as ANY when neither explicit
        prerequisite field is populated, matching the original engine.
        """
        if self.requires_all or self.requires_any:
            return list(self.requires_any)
        return list(self.requires)

    def to_dict(self) -> Dict[str, Any]:
        serialized = asdict(self)
        serialized.pop("http_request_context", None)
        return serialized

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Construct a canonical finding from a dictionary."""
        if not isinstance(data, dict):
            raise TypeError("finding data must be a dictionary")

        normalized = dict(data)
        aliases = {
            "id": "finding_id",
            "affected_endpoint": "endpoint",
            "raw_evidence_url": "endpoint",
            "timestamp": "observed_at",
            "status": "validation_status",
            "confidence_score": "validation_confidence",
            "validator": "source",
            "grants": "provides",
        }
        for old_name, new_name in aliases.items():
            if new_name not in normalized and old_name in normalized:
                normalized[new_name] = normalized[old_name]

        required = (
            "finding_id",
            "scan_id",
            "asset_id",
            "target",
            "host",
            "source",
            "vulnerability_type",
        )
        missing = [name for name in required if name not in normalized]
        if missing:
            raise ValueError(
                "missing required Finding fields: " + ", ".join(missing)
            )

        fields = cls.__dataclass_fields__
        return cls(**{key: value for key, value in normalized.items() if key in fields})

    @classmethod
    def from_legacy_evidence(
        cls,
        entry: Dict[str, Any],
        *,
        scan_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        host: Optional[str] = None,
    ) -> "Finding":
        """
        Adapt a legacy evidence record when required assessment context is supplied.

        Required context is never replaced with synthetic "unknown" identifiers.
        """
        if not isinstance(entry, dict):
            raise TypeError("legacy evidence must be a dictionary")

        data = dict(entry)
        if scan_id is not None:
            data.setdefault("scan_id", scan_id)
        if asset_id is not None:
            data.setdefault("asset_id", asset_id)
        if host is not None:
            data.setdefault("host", host)

        data.setdefault("source", data.get("validator"))
        data.setdefault("vulnerability_type", data.get("template_id"))

        status = data.get(
            "validation_status",
            data.get("status", ValidationStatus.DETECTED),
        )
        data["validation_status"] = status

        if "validation_confidence" not in data:
            if "confidence_score" in data:
                data["validation_confidence"] = data["confidence_score"]
            else:
                normalized_status = ValidationStatus.normalize(status)
                data["validation_confidence"] = STATUS_WEIGHT[normalized_status]

        data.setdefault("raw_finding_ref", data.get("finding_id", data.get("id")))
        return cls.from_dict(data)


# Compatibility name retained for existing imports while Finding becomes canonical.
NormalizedFinding = Finding
