"""Request/response evidence capture and replay.

This is the Obsidian-native adaptation of VulnClaw's ``traffic/store.py`` and
``traffic/replay.py``: every validator/tool interaction that matters can be
recorded as a bounded :class:`EvidenceEntry` and later replayed with explicit
overrides. Replay is what makes a finding *reproducible* — the same request can
be re-issued against the authorized target to confirm that a result still holds,
without re-running the whole discovery pipeline.

Design rules (consistent with the automation layer):

* **Bounded** — bodies and header values are truncated, entry counts are capped.
* **Deterministic / off-target safe** — replay only re-issues the recorded URL;
  callers should pass a scope-checked URL. This module never *chooses* a target.
* **Fail-soft** — capture and replay never raise to the caller.
* **JSON-safe** — the store serializes to plain JSON for artifact storage.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

_MAX_BODY = 200_000
_MAX_HEADER_VALUE = 4_000
_MAX_HEADERS = 64
_MAX_ENTRIES = 500


def _bound(value: Any, maximum: int) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= maximum else text[: maximum - 1] + "\u2026"


def _bound_headers(headers: Any) -> Dict[str, str]:
    if not headers:
        return {}
    items = headers.items() if hasattr(headers, "items") else (headers or [])
    result: Dict[str, str] = {}
    for key, value in list(items)[:_MAX_HEADERS]:
        result[_bound(key, 256)] = _bound(value, _MAX_HEADER_VALUE)
    return result


@dataclass
class EvidenceEntry:
    """One captured request/response exchange."""

    method: str
    url: str
    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    finding_id: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    duration_ms: int = 0
    created_at: float = field(default_factory=time.time)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceEntry":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{key: value for key, value in (data or {}).items() if key in known})


class EvidenceStore:
    """Bounded, JSON-serializable evidence store.

    Not thread-safe by design; callers that dispatch in parallel should record
    through a lock or a single collector (see :mod:`app.automation.dispatch`).
    """

    def __init__(self, *, max_entries: int = _MAX_ENTRIES) -> None:
        self._entries: List[EvidenceEntry] = []
        self._max_entries = max(1, int(max_entries))

    # -- capture -------------------------------------------------------------
    def record(self, entry: EvidenceEntry) -> EvidenceEntry:
        self._entries.append(entry)
        # Drop the oldest entries to stay bounded.
        overflow = len(self._entries) - self._max_entries
        if overflow > 0:
            del self._entries[:overflow]
        return entry

    def record_exchange(
        self,
        method: str,
        url: str,
        *,
        request_headers: Any = None,
        request_body: Optional[str] = None,
        response: Any = None,
        status_code: Optional[int] = None,
        response_headers: Any = None,
        response_body: Optional[str] = None,
        finding_id: Optional[str] = None,
        duration_ms: int = 0,
        meta: Optional[Dict[str, Any]] = None,
    ) -> EvidenceEntry:
        """Capture one exchange from a requests/httpx-style response object."""
        if response is not None:
            status_code = status_code if status_code is not None else getattr(response, "status_code", None)
            response_headers = response_headers if response_headers is not None else getattr(response, "headers", None)
            if response_body is None:
                response_body = getattr(response, "text", None)
        entry = EvidenceEntry(
            method=str(method or "GET").upper(),
            url=str(url or ""),
            finding_id=finding_id,
            request_headers=_bound_headers(request_headers),
            request_body=_bound(request_body, _MAX_BODY) if request_body is not None else None,
            status_code=status_code,
            response_headers=_bound_headers(response_headers),
            response_body=_bound(response_body, _MAX_BODY) if response_body is not None else None,
            duration_ms=duration_ms,
            meta={k: v for k, v in (meta or {}).items() if isinstance(k, str)},
        )
        return self.record(entry)

    # -- query ---------------------------------------------------------------
    def all(self) -> List[EvidenceEntry]:
        return list(self._entries)

    def recent(self, count: int = 10) -> List[EvidenceEntry]:
        return list(self._entries[-max(1, int(count)):])

    def for_finding(self, finding_id: Optional[str]) -> List[EvidenceEntry]:
        return [e for e in self._entries if e.finding_id == finding_id]

    def __len__(self) -> int:
        return len(self._entries)

    # -- replay --------------------------------------------------------------
    def replay(
        self,
        entry: EvidenceEntry,
        *,
        overrides: Optional[Dict[str, Any]] = None,
        http_session: Any = None,
        timeout: int = 15,
    ) -> EvidenceEntry:
        """Re-issue a recorded request with optional overrides.

        ``overrides`` may set ``method``, ``url``, ``headers`` (merged),
        ``body`` (replaces), and ``params``. The replayed exchange is recorded
        and returned. Never raises: a transport error yields an entry whose
        ``meta['error']`` is set.
        """
        overrides = dict(overrides or {})
        method = str(overrides.get("method") or entry.method or "GET").upper()
        url = str(overrides.get("url") or entry.url)
        headers = dict(entry.request_headers)
        headers.update(_bound_headers(overrides.get("headers")))
        if "body" in overrides:
            body: Optional[str] = overrides.get("body")
        else:
            body = entry.request_body
        params = overrides.get("params")

        started = time.monotonic()
        try:
            session = http_session
            if session is None:
                import requests

                session = requests.Session()
            response = session.request(
                method,
                url,
                headers=headers or None,
                data=body,
                params=params,
                timeout=timeout,
                allow_redirects=False,
            )
        except Exception as exc:  # noqa: BLE001 — replay is best-effort
            replayed = EvidenceEntry(
                method=method,
                url=url,
                finding_id=entry.finding_id,
                request_headers=headers,
                request_body=body,
                meta={"replay_of": entry.entry_id, "error": f"{type(exc).__name__}: {exc}"[:512]},
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            return self.record(replayed)
        return self.record_exchange(
            method,
            url,
            request_headers=headers,
            request_body=body,
            response=response,
            finding_id=entry.finding_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            meta={"replay_of": entry.entry_id},
        )

    # -- persistence ---------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], ensure_ascii=False)

    def save(self, path: str) -> bool:
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as handle:
                handle.write(self.to_json())
            return True
        except OSError:
            return False

    @classmethod
    def load(cls, path: str, *, max_entries: int = _MAX_ENTRIES) -> "EvidenceStore":
        store = cls(max_entries=max_entries)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return store
        for item in data if isinstance(data, list) else []:
            if isinstance(item, dict):
                store.record(EvidenceEntry.from_dict(item))
        return store


__all__ = ["EvidenceEntry", "EvidenceStore"]
