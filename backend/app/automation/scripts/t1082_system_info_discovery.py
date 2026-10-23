"""T1082 — System Information Discovery.

After command execution is established, collect host/system facts (OS, kernel,
user, environment) **on the target**. Two paths, both target-side:

* **Session path** — when an authenticated target session is available, a fixed,
  bounded facts command runs through the session and the target's output is
  parsed. Evidence identifies the session (host/port/user) so the facts are
  attributed to a specific target.
* **HTTP path** — otherwise the deterministic system-information discovery
  validator runs against the finding endpoint.

Grants the ``system_information`` capability used by the privilege-escalation
techniques. Enumeration alone is never treated as elevated access.
"""
from __future__ import annotations

import time
from dataclasses import replace
from typing import Optional

from app.automation import register
from app.automation import adapters
from app.automation import session as session_adapters
from app.automation.base import AutomationContext, TechniqueResult, TechniqueScript, TechniqueStatus

_VALIDATOR_ID = "controlled-http-system-information-discovery"
_FACTS_COMMAND = "uname -a; echo '---'; id; echo '---'; hostname"


@register
class SystemInformationDiscovery(TechniqueScript):
    """Discover host/system information (MITRE T1082)."""

    technique_id = "T1082"
    name = "System Information Discovery"
    tactic = "Discovery"
    description = (
        "Collect OS/kernel/user/environment facts through an authenticated "
        "target session or the deterministic system-information validator."
    )
    requires_any = ("command_execution",)
    provides = ("system_information",)
    vuln_types = (
        "system-information-discovery",
        "information-disclosure",
        "command-execution",
        "command_injection",
        "rce",
    )
    allowed_options = ("endpoint", "http_method", "parameter_name", "parameter_location")
    automatic_allowed = True

    def execute(self, ctx: AutomationContext) -> TechniqueResult:
        started = time.time()
        target_session: Optional[object] = session_adapters.open_context_session(ctx)
        if target_session is not None:
            return self._execute_with_session(ctx, target_session, started)
        return self._execute_with_validator(ctx, started)

    # -- session path --------------------------------------------------------
    def _execute_with_session(
        self, ctx: AutomationContext, target_session: object, started: float
    ) -> TechniqueResult:
        info = getattr(target_session, "info", None)
        identity = info.describe() if hasattr(info, "describe") else {"kind": "session"}
        try:
            command = target_session.run(  # type: ignore[attr-defined]
                _FACTS_COMMAND, timeout=min(int(ctx.timeout_seconds or 60), 120)
            )
        except Exception as exc:  # noqa: BLE001 — fail-soft
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.ERROR,
                summary="target session facts collection could not complete.",
                error=f"{type(exc).__name__}: {exc}"[:512],
                evidence={"session": identity, "command": _FACTS_COMMAND},
                duration_ms=int((time.time() - started) * 1000),
            )

        output = command.stdout or ""
        # Confirmation requires real host facts, not just an empty/echoed reply.
        has_kernel = "Linux" in output or "GNU/Linux" in output
        has_identity = "uid=" in output or "gid=" in output
        confirmed = command.rc == 0 and (has_kernel or has_identity)
        evidence = {
            "path": "session",
            "session": identity,
            "command": _FACTS_COMMAND,
            "rc": command.rc,
            "kernel_identified": has_kernel,
            "identity_identified": has_identity,
            "output": output[:2000],
        }
        if confirmed:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.CONFIRMED,
                summary="system information discovered through a target session.",
                provides=self.provides,
                evidence=evidence,
                next_techniques=("T1548", "T1068"),
                duration_ms=int((time.time() - started) * 1000),
            )
        return TechniqueResult(
            technique_id=self.technique_id,
            status=TechniqueStatus.INCONCLUSIVE,
            summary="target session returned no parseable host facts.",
            evidence=evidence,
            duration_ms=int((time.time() - started) * 1000),
        )

    # -- HTTP validator path --------------------------------------------------
    def _execute_with_validator(self, ctx: AutomationContext, started: float) -> TechniqueResult:
        finding = ctx.finding
        if finding is None:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.SKIPPED,
                summary="no finding or session supplied; T1082 needs a target.",
            )

        probe = replace(finding, validator_id=_VALIDATOR_ID)
        try:
            validation = adapters.run_validator(probe, ctx.http_session)
        except Exception as exc:  # noqa: BLE001
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.ERROR,
                summary="system-information discovery could not complete.",
                error=str(exc)[:512],
                duration_ms=int((time.time() - started) * 1000),
            )

        status = adapters.validator_status_to_technique_status(validation.status)
        evidence = {
            "path": "http-validator",
            "validator_id": _VALIDATOR_ID,
            "status": validation.status,
            "confidence": validation.confidence,
            "detail": (validation.evidence or {}).get("reason")
            or (validation.evidence or {}).get("decision"),
        }
        if status == TechniqueStatus.CONFIRMED:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.CONFIRMED,
                summary="system information discovered.",
                provides=self.provides,
                evidence=evidence,
                next_techniques=("T1548", "T1068"),
                duration_ms=int((time.time() - started) * 1000),
            )
        return TechniqueResult(
            technique_id=self.technique_id,
            status=status,
            summary=f"system information not confirmed ({validation.status}).",
            evidence=evidence,
            duration_ms=int((time.time() - started) * 1000),
        )
