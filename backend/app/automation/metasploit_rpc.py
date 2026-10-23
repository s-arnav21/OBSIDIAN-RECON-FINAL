"""Optional Metasploit RPC adapter.

Obsidian already ships two Metasploit *tools* that shell out to ``msfconsole``.
This module provides the alternative, language-native integration the mapping
calls for: drive an existing Metasploit instance through its RPC daemon
(``msfrpcd``) using ``pymetasploit3``.

Everything here is **gated on availability** — importing this module never fails
when ``pymetasploit3`` is absent, and every call returns a bounded, structured
result instead of raising. It controls an *existing* Metasploit installation; it
does not install or discover one, and it never decides that a lab scenario is
authorized (that is the policy gate's job).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:  # optional dependency — never break import
    from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore

    _IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    MsfRpcClient = None  # type: ignore
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


def available() -> bool:
    return MsfRpcClient is not None


def availability() -> Dict[str, Any]:
    return {
        "available": available(),
        "package": "pymetasploit3",
        "daemon": "msfrpcd",
        "reason": None if available() else _IMPORT_ERROR,
    }


def connect(
    *,
    password: str,
    host: str = "127.0.0.1",
    port: int = 55552,
    username: str = "msf",
    ssl: bool = False,
    timeout: int = 15,
) -> Any:
    """Connect to an existing ``msfrpcd``. Raises ``MetasploitUnavailable``."""
    if MsfRpcClient is None:
        raise MetasploitUnavailable(_IMPORT_ERROR or "pymetasploit3 not installed")
    return MsfRpcClient(
        password,
        server=host,
        port=port,
        username=username,
        ssl=ssl,
        timeout=timeout,
    )


def sessions(client: Any) -> List[Dict[str, Any]]:
    """Return a bounded list of active Metasploit sessions."""
    try:
        raw = client.sessions.list or {}
    except Exception:  # noqa: BLE001 — fail-soft
        return []
    result: List[Dict[str, Any]] = []
    for session_id, meta in list(raw.items())[:50]:
        if not isinstance(meta, dict):
            continue
        result.append({
            "id": str(session_id),
            "type": str(meta.get("type", "")),
            "tunnel_peer": str(meta.get("tunnel_peer", "")),
            "info": str(meta.get("info", ""))[:512],
        })
    return result


def run_module(
    client: Any,
    *,
    module_type: str,
    module_name: str,
    options: Optional[Dict[str, Any]] = None,
    wait_seconds: int = 30,
) -> Dict[str, Any]:
    """Run one Metasploit module and return a bounded outcome.

    This is intentionally thin: authorization/policy decisions happen upstream.
    """
    outcome: Dict[str, Any] = {
        "module": f"{module_type}/{module_name}",
        "executed": False,
        "job_id": None,
        "session_created": None,
        "error": None,
    }
    if MsfRpcClient is None:
        outcome["error"] = _IMPORT_ERROR or "pymetasploit3 not installed"
        return outcome
    try:
        module = client.modules.use(module_type, module_name)
        for key, value in (options or {}).items():
            module[key] = value
        job_id = module.execute()
        outcome["executed"] = True
        outcome["job_id"] = str(job_id)
        created = sessions(client)
        if created:
            outcome["session_created"] = created[-1]["id"]
    except Exception as exc:  # noqa: BLE001 — fail-soft
        outcome["error"] = f"{type(exc).__name__}: {exc}"[:512]
    return outcome


class MetasploitUnavailable(RuntimeError):
    """Raised only when a caller explicitly connects without the dependency."""


__all__ = [
    "available",
    "availability",
    "connect",
    "sessions",
    "run_module",
    "MetasploitUnavailable",
]
