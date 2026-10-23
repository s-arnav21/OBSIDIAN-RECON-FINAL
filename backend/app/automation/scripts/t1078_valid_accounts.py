"""T1078 — Valid Accounts.

Attempts to obtain access by testing common/default credentials against a
discovered login service (web form, SSH, FTP). Uses the bounded ``hydra``
brute-force tool when present; otherwise reports the technique as unavailable
rather than guessing.

**Honest capability split.** Recovering credential *material* and holding a
reusable *session* are different results:

* ``credential_access`` is granted when hydra recovers accepted credentials.
* ``authenticated_session`` is granted only when a session is actually
  established — either a ready target session on the context, or an SSH session
  opened (and authenticated) with the recovered credentials.

Credentials that were recovered but never validated against a session therefore
do not claim a session.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.automation import register
from app.automation import adapters
from app.automation import session as session_adapters
from app.automation.base import AutomationContext, TechniqueResult, TechniqueScript, TechniqueStatus

_SERVICE_HINTS = (
    ("ssh", "ssh"),
    ("ftp", "ftp"),
    ("smb", "smb"),
    ("rdp", "rdp"),
    ("mysql", "mysql"),
)


def _guess_service(ctx: AutomationContext) -> str:
    merged = ctx.merged_options()
    hint = " ".join(str(merged.get(k, "")) for k in ("vulnerability_type", "service", "endpoint")).lower()
    for token, service in _SERVICE_HINTS:
        if token in hint:
            return service
    return "http-post-form"


def _tool_options(ctx: AutomationContext) -> Dict[str, str]:
    merged = ctx.merged_options()
    endpoint = str(merged.get("endpoint") or ctx.target)
    if not endpoint.startswith(("http://", "https://")):
        endpoint = ctx.target.rstrip("/") + "/" + endpoint.lstrip("/")
    options: Dict[str, str] = {"target": endpoint}
    service = _guess_service(ctx)
    options["service"] = service
    if service == "http-post-form":
        options["login_url"] = "/login"
    return options


def _target_host(ctx: AutomationContext) -> str:
    raw = ctx.target or ""
    parsed = urlparse(raw if "://" in raw else "//" + raw)
    return parsed.hostname or raw


def _first_pair(creds: List[Any]) -> Optional[Tuple[str, str]]:
    for item in creds:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            return str(item[0]), str(item[1])
    return None


def _validate_recovered_credentials(
    ctx: AutomationContext, creds: List[Any], service: str
) -> Tuple[Optional[object], Optional[str]]:
    """Return ``(session, reason)`` for the recovered credentials.

    A ready context session always counts. Otherwise an SSH session is opened
    with the first recovered pair; other services cannot currently be proven to
    yield a reusable session, so they return ``"unvalidated_service"``.
    """
    ready = getattr(ctx, "session", None)
    if ready is not None:
        return ready, None
    if service != "ssh":
        return None, "unvalidated_service"
    pair = _first_pair(creds)
    if pair is None:
        return None, "no_credential_pair"
    user, password = pair
    options = {
        "ssh_host": _target_host(ctx),
        "ssh_user": user,
        "ssh_password": password,
    }
    session, reason = session_adapters.try_open_ssh_session(options, connect_timeout=10)
    if session is not None:
        # Validation only; the session is closed after proving it authenticates.
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
    return session, reason


@register
class ValidAccounts(TechniqueScript):
    """Obtain a valid account session (MITRE T1078)."""

    technique_id = "T1078"
    name = "Valid Accounts"
    tactic = "Initial Access / Persistence / Privilege Escalation"
    description = (
        "Test common/default credentials against a discovered login service and, "
        "when possible, validate that the recovered credentials establish a "
        "reusable session."
    )
    requires_any = ("discovered_services", "reachable_login_service", "unauthenticated")
    provides = ("authenticated_session", "credential_access")
    vuln_types = ("default-credentials", "weak-credentials", "valid-accounts", "brute-force")
    allowed_options = ("endpoint",)
    automatic_allowed = True

    def execute(self, ctx: AutomationContext) -> TechniqueResult:
        started = time.time()
        if not adapters.tool_available("hydra-brute"):
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.BLOCKED,
                summary="hydra is not installed; credential testing is unavailable.",
                error="missing_binary:hydra",
                duration_ms=int((time.time() - started) * 1000),
            )

        service = _guess_service(ctx)
        result = adapters.run_real_tool("hydra-brute", _tool_options(ctx))
        creds = list(getattr(result, "extra", {}).get("credentials", []) or [])
        artifact = adapters.write_artifact(
            ctx, "t1078_hydra.txt", getattr(result, "raw", "") or result.output
        )
        evidence: Dict[str, Any] = {
            "tool": "hydra-brute",
            "success": bool(result.success),
            "service": service,
            "credential_count": len(creds),
            "credentials_found": bool(creds),
            "output": (result.output or "")[:2000],
        }
        artifacts = (artifact,) if artifact else ()

        if not (result.success and creds):
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.REJECTED,
                summary="no default credentials accepted.",
                evidence=evidence,
                artifacts=artifacts,
                duration_ms=int((time.time() - started) * 1000),
            )

        # Credentials accepted. Prove a reusable session separately.
        session, reason = _validate_recovered_credentials(ctx, creds, service)
        session_validated = session is not None
        evidence["session_validated"] = session_validated
        evidence["session_reason"] = reason
        if hasattr(getattr(session, "info", None), "describe"):
            evidence["session"] = session.info.describe()  # type: ignore[attr-defined]

        provides = ["credential_access"]
        next_techniques: Tuple[str, ...] = ("T1213",)
        if session_validated:
            provides.append("authenticated_session")
            next_techniques = ("T1059.004", "T1082", "T1213")
            summary = "valid credentials recovered and a target session established."
        else:
            summary = (
                "valid credentials recovered but no reusable session validated "
                f"({reason})."
            )
        return TechniqueResult(
            technique_id=self.technique_id,
            status=TechniqueStatus.CONFIRMED,
            summary=summary,
            provides=tuple(provides),
            evidence=evidence,
            artifacts=artifacts,
            next_techniques=next_techniques,
            duration_ms=int((time.time() - started) * 1000),
        )
