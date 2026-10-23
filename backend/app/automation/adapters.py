"""Thin adapters from technique scripts to the existing execution layers.

Technique scripts should not reach into the agent tool registry or the
validation dispatcher directly. They call these helpers, which keep the
technique layer decoupled and testable (each function can be monkeypatched in
tests without an LLM or a live target).
"""
from __future__ import annotations

from typing import Any, Optional

from app.models.finding import Finding
from app.models.validation import ValidationResult
from app.scanning.scope import AuthorizedTarget, ReconScopeError, normalize_origin


def normalize_target(target: str) -> AuthorizedTarget:
    """Return the canonical authorization object for a target URL."""
    return normalize_origin(target)


def is_valid_target(target: str) -> bool:
    try:
        normalize_origin(target)
        return True
    except ReconScopeError:
        return False


def resolve_http_session(session: Any) -> Any:
    """Return an HTTP-capable session (mirrors AgentToolExecutor behavior).

    Callers thread the SQLAlchemy DB session through the executor; validators
    need a ``requests``-style session. A database session is replaced with a
    fresh HTTP session so validators run instead of degrading to manual review.
    """
    if session is None:
        import requests

        return requests.Session()
    # A DB session has ``execute``/``get`` but not ``get``/``post`` HTTP verbs
    # with the requests signature; detect the requests/httpx surface instead.
    if hasattr(session, "request") and hasattr(session, "get"):
        return session
    import requests

    return requests.Session()


def run_validator(finding: Finding, session: Any = None) -> ValidationResult:
    """Dispatch the finding's registered canonical validator."""
    from app.validation.dispatcher import dispatch

    return dispatch(finding, session=resolve_http_session(session))


def run_real_tool(tool_id: str, options: dict) -> Any:
    """Execute a registered external tool by id and return its ToolResult."""
    from app.agent.tools import execute_tool

    return execute_tool(tool_id, options)


def tool_available(tool_id: str) -> bool:
    """Return True when a tool can actually be dispatched (binary or RPC)."""
    from app.agent.tools import TOOL_REGISTRY, _tool_is_available

    tool = TOOL_REGISTRY.get(tool_id)
    if tool is None:
        return False
    return _tool_is_available(tool)


def scoped_http(target: str) -> Any:
    """Return a scoped HTTP client context manager for one authorized origin.

    ``ScopedReconHttpClient`` only talks to the exact origin handed to it, so
    technique scripts cannot be steered off-target by an LLM-supplied URL.
    """
    from app.scanning.http_discovery import ScopedReconHttpClient

    return ScopedReconHttpClient(normalize_origin(target))


def validator_status_to_technique_status(status: str) -> str:
    """Map a ValidationStatus onto a TechniqueStatus constant."""
    from app.automation.base import TechniqueStatus
    from app.models.finding import ValidationStatus

    mapping = {
        ValidationStatus.CONFIRMED: TechniqueStatus.CONFIRMED,
        ValidationStatus.REJECTED: TechniqueStatus.REJECTED,
        ValidationStatus.LIKELY: TechniqueStatus.INCONCLUSIVE,
        ValidationStatus.DETECTED: TechniqueStatus.INCONCLUSIVE,
        ValidationStatus.MANUAL_REVIEW: TechniqueStatus.INCONCLUSIVE,
        ValidationStatus.ERROR: TechniqueStatus.ERROR,
    }
    return mapping.get(status, TechniqueStatus.INCONCLUSIVE)


def artifact_path(ctx: Any, filename: str) -> Optional[str]:
    """Return an artifact path inside the context dir, creating it if needed."""
    import os

    if not ctx.artifact_dir:
        return None
    os.makedirs(ctx.artifact_dir, exist_ok=True)
    safe = os.path.basename(filename)
    return os.path.join(ctx.artifact_dir, safe)


def write_artifact(ctx: Any, filename: str, content: str) -> Optional[str]:
    """Persist bounded tool output to the artifact dir; never raise."""
    path = artifact_path(ctx, filename)
    if path is None:
        return None
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as handle:
            handle.write(content[:5_000_000])
        return path
    except OSError:
        return None


__all__ = [
    "normalize_target",
    "is_valid_target",
    "resolve_http_session",
    "run_validator",
    "run_real_tool",
    "tool_available",
    "scoped_http",
    "validator_status_to_technique_status",
    "artifact_path",
    "write_artifact",
]
