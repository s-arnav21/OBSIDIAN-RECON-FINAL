"""Raw scanner finding model — scanner-specific output before normalization."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RawFinding:
    """A raw finding as produced by a scanner (Nmap, Nuclei, built-in probe).

    This is scanner-specific output. It is NOT the canonical Finding — the
    normalizer layer converts RawFinding -> Finding, resolving vulnerability
    aliases and selecting a validator_id.

    Fields intentionally mirror the broad set of attributes a scanner might
    emit, with a compact 'raw' dict preserving scanner-native detail.
    """
    scanner: str                    # "nmap" | "nuclei" | "http_probe"
    scanner_template_id: str        # e.g. "nuclei-sqli", "open-port", "missing-security-header"
    vulnerability_type: Optional[str] = None
    target: str = ""
    host: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    severity: str = "medium"
    url: Optional[str] = None
    path: Optional[str] = None
    extraction: Optional[str] = None
    matched_at: Optional[str] = None
    description: str = ""
    raw: dict = field(default_factory=dict)
    evidence_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "scanner_template_id": self.scanner_template_id,
            "vulnerability_type": self.vulnerability_type,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "severity": self.severity,
            "url": self.url,
            "path": self.path,
            "extraction": self.extraction,
            "matched_at": self.matched_at,
            "description": self.description,
            "raw": self.raw,
            "evidence_id": self.evidence_id,
        }
