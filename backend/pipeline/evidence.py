"""Evidence store — raw per-scanner output retained with each finding.

Every scanner writes raw stdout/stderr; the evidence store keeps it alongside
structured findings so downstream triage, validation, and normalization have
real artifacts to work over rather than just summary counts.

Design:
  - `Evidence` is a small immutable-ish dataclass (id, scanner, raw_output,
    sha256, timestamp, target_url, size_bytes).
  - `EvidenceStore` is a dict-like registry keyed by evidence_id with a
    sequence generator (e001, e002, ...).
  - Each `RawFinding` can carry an `evidence_id` linking back to the source
    evidence blob.

Size guard: a scanner's raw output is capped (MAX_EVIDENCE_BYTES) so memory
stays bounded even on chatty scanners.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from app.models.scanner import RawFinding

MAX_EVIDENCE_BYTES = 200_000


def _sha256(text: str) -> str:
    if not text:
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class Evidence:
    evidence_id: str
    scanner: str
    raw_output: str
    sha256: str
    timestamp: str
    target_url: str
    size_bytes: int
    tool_command: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "scanner": self.scanner,
            "raw_output": self.raw_output,
            "sha256": self.sha256,
            "timestamp": self.timestamp,
            "target_url": self.target_url,
            "size_bytes": self.size_bytes,
            "tool_command": self.tool_command,
        }


class EvidenceStore:
    """Registry of evidence blobs with a monotonic evidence_id generator."""

    def __init__(self) -> None:
        self._items: dict[str, Evidence] = {}
        self._counter = 0

    def add(self, scanner: str, raw_output: str, target_url: str = "",
            tool_command: Optional[str] = None) -> str:
        """Store raw output and return its evidence_id."""
        self._counter += 1
        eid = f"e{self._counter:03d}"
        truncated = raw_output[:MAX_EVIDENCE_BYTES]
        ts = datetime.now(timezone.utc).isoformat()
        self._items[eid] = Evidence(
            evidence_id=eid,
            scanner=scanner,
            raw_output=truncated,
            sha256=_sha256(raw_output),
            timestamp=ts,
            target_url=target_url,
            size_bytes=len(truncated),
            tool_command=tool_command,
        )
        return eid

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._items.get(evidence_id)

    def __contains__(self, evidence_id: str) -> bool:
        return evidence_id in self._items

    def __len__(self) -> int:
        return len(self._items)

    def to_dict(self) -> dict[str, dict]:
        return {eid: ev.to_dict() for eid, ev in self._items.items()}

    def items(self):
        return self._items.items()

    def keys(self):
        return list(self._items.keys())


def build_evidence(finding: RawFinding, evidence_id: str) -> RawFinding:
    """Return a copy of the finding with evidence_id linked. Mutates in place."""
    finding.raw = dict(finding.raw or {})
    finding.raw["evidence_id"] = evidence_id
    return finding