"""Structured output contract for evidence validation handlers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.models.finding import (
    ValidationStatus,
    _require_non_empty_string,
    validate_confidence,
)


@dataclass
class ValidationResult:
    """Result returned by a validation handler or manual-review decision."""

    status: str = "manual_review"
    confidence: float = 0.0
    validator: str = ""
    method: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error: Optional[str] = None

    def __post_init__(self) -> None:
        self.status = ValidationStatus.normalize(self.status)
        self.confidence = validate_confidence(self.confidence)
        if self.validator:
            _require_non_empty_string(self.validator, "validator")
        if self.method:
            _require_non_empty_string(self.method, "method")
        _require_non_empty_string(self.timestamp, "timestamp")

        if not isinstance(self.evidence, dict):
            raise TypeError("evidence must be a dictionary")
        if not isinstance(self.evidence_refs, list) or not all(
            isinstance(ref, str) and ref for ref in self.evidence_refs
        ):
            raise TypeError("evidence_refs must be a list of non-empty strings")
        if self.error is not None and not isinstance(self.error, str):
            raise TypeError("error must be a string or None")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationResult":
        if not isinstance(data, dict):
            raise TypeError("validation result data must be a dictionary")
        return cls(**data)
