"""mitmproxy capture -> EvidenceStore.

Feeds captured HTTP flows into :class:`app.automation.evidence.EvidenceStore`
so captured traffic becomes replayable evidence. The conversion is duck-typed
against the mitmproxy ``HTTPFlow`` shape, so it can be unit-tested with a stub
and does not require mitmproxy to be importable.

An ``EvidenceCaptureAddon`` is provided for use as a mitmproxy addon::

    from app.automation.evidence import EvidenceStore
    from app.automation.mitm_capture import EvidenceCaptureAddon
    store = EvidenceStore()
    addons = [EvidenceCaptureAddon(store)]

mitmproxy remains optional; this module never imports it at module load.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Optional

from app.automation.evidence import EvidenceEntry, EvidenceStore


def available() -> bool:
    """Return True when the optional mitmproxy dependency is importable."""
    try:
        import mitmproxy  # type: ignore  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


def _request_text(request: Any) -> Optional[str]:
    for attr in ("get_text", "text"):
        value = getattr(request, attr, None)
        if callable(value):
            try:
                value = value()
            except Exception:  # noqa: BLE001
                value = None
        if isinstance(value, str):
            return value
    content = getattr(request, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8", "replace")
    return None


def _url(request: Any) -> str:
    for attr in ("pretty_url", "url"):
        value = getattr(request, attr, None)
        if isinstance(value, str) and value:
            return value
    return ""


def flow_to_entry(flow: Any, *, finding_id: Optional[str] = None) -> Optional[EvidenceEntry]:
    """Convert one mitmproxy flow into an :class:`EvidenceEntry`.

    Returns None when the flow has no request. Never raises.
    """
    request = getattr(flow, "request", None)
    if request is None:
        return None
    response = getattr(flow, "response", None)
    try:
        entry = EvidenceEntry(
            method=str(getattr(request, "method", "GET") or "GET").upper(),
            url=_url(request),
            finding_id=finding_id,
            request_headers=dict(getattr(request, "headers", {}) or {}),
            request_body=_request_text(request),
            status_code=getattr(response, "status_code", None) if response is not None else None,
            response_headers=dict(getattr(response, "headers", {}) or {}) if response is not None else {},
            response_body=_response_text(response) if response is not None else None,
            meta={"source": "mitmproxy"},
        )
    except Exception:  # noqa: BLE001 — fail-soft
        return None
    return entry


def _response_text(response: Any) -> Optional[str]:
    for attr in ("get_text", "text"):
        value = getattr(response, attr, None)
        if callable(value):
            try:
                value = value()
            except Exception:  # noqa: BLE001
                value = None
        if isinstance(value, str):
            return value
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8", "replace")
    return None


def capture_from_flows(
    flows: Iterable[Any], store: EvidenceStore, *, finding_id: Optional[str] = None
) -> int:
    """Record every convertible flow; return the number recorded."""
    recorded = 0
    for flow in flows:
        entry = flow_to_entry(flow, finding_id=finding_id)
        if entry is not None:
            store.record(entry)
            recorded += 1
    return recorded


class EvidenceCaptureAddon:
    """mitmproxy addon that records responses into an EvidenceStore."""

    def __init__(self, store: EvidenceStore, *, finding_id: Optional[str] = None) -> None:
        self.store = store
        self.finding_id = finding_id
        self.captured: List[EvidenceEntry] = []

    def response(self, flow: Any) -> None:
        entry = flow_to_entry(flow, finding_id=self.finding_id)
        if entry is not None:
            self.store.record(entry)
            self.captured.append(entry)


__all__ = [
    "available",
    "flow_to_entry",
    "capture_from_flows",
    "EvidenceCaptureAddon",
]
