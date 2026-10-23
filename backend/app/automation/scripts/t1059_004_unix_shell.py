"""T1059.004 — Command and Scripting Interpreter: Unix Shell.

Establishes command execution on the authorized target. Two execution paths,
both of which run *on the target* — never locally on the Obsidian host:

* **Session path** — when an authenticated target session is available (a
  Paramiko SSH session supplied on the context or opened from recovered
  credentials), a fixed, bounded marker command is executed *through the
  session* and confirmation requires the target's own output to contain the
  marker. The session identity is recorded in the evidence so the claim names
  the host it ran against.
* **HTTP path** — otherwise the deterministic command-execution validator issues
  fixed, bounded marker probes against the finding endpoint.

Either way the planner never authors a payload.
"""
from __future__ import annotations

import time
from dataclasses import replace
from typing import Optional

from app.automation import register
from app.automation import adapters
from app.automation import session as session_adapters
from app.automation.base import AutomationContext, TechniqueResult, TechniqueScript, TechniqueStatus

_VALIDATOR_ID = "generic-http-command-execution"
_MARKER = "obsidian-cmdexec-ok"
_MARKER_COMMAND = f"echo {_MARKER}; id -u 2>/dev/null || true"


@register
class UnixShellExecution(TechniqueScript):
    """Establish command execution (MITRE T1059.004)."""

    technique_id = "T1059.004"
    name = "Command and Scripting Interpreter: Unix Shell"
    tactic = "Execution"
    description = (
        "Confirm OS command execution on the target, either through an "
        "authenticated target session or via the deterministic command-"
        "execution validator on the finding endpoint."
    )
    requires_any = ("application_compromise",)
    provides = ("command_execution",)
    vuln_types = ("rce", "command-execution", "command_injection", "remote_code_execution")
    allowed_options = ("endpoint", "http_method", "parameter_name", "parameter_location")
    automatic_allowed = True

    def execute(self, ctx: AutomationContext) -> TechniqueResult:
        started = time.time()
        # A ready or derivable target session takes priority: it is the most
        # direct proof that the command ran on the target, not on the host.
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
                _MARKER_COMMAND, timeout=min(int(ctx.timeout_seconds or 60), 120)
            )
        except Exception as exc:  # noqa: BLE001 — fail-soft
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.ERROR,
                summary="target session command could not complete.",
                error=f"{type(exc).__name__}: {exc}"[:512],
                evidence={"session": identity, "command": _MARKER_COMMAND},
                duration_ms=int((time.time() - started) * 1000),
            )

        marker_found = _MARKER in (command.stdout or "")
        evidence = {
            "path": "session",
            "session": identity,
            "command": _MARKER_COMMAND,
            "rc": command.rc,
            "marker_found": marker_found,
            "output": (command.stdout or "")[:2000],
        }
        if marker_found:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.CONFIRMED,
                summary="OS command execution confirmed through a target session.",
                provides=self.provides,
                evidence=evidence,
                next_techniques=("T1082", "T1548", "T1213"),
                duration_ms=int((time.time() - started) * 1000),
            )
        return TechniqueResult(
            technique_id=self.technique_id,
            status=TechniqueStatus.REJECTED,
            summary="target session ran but the marker was absent; execution not confirmed.",
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
                summary="no finding or session supplied; T1059.004 needs a target.",
            )

        probe = replace(finding, validator_id=_VALIDATOR_ID)
        try:
            validation = adapters.run_validator(probe, ctx.http_session)
        except Exception as exc:  # noqa: BLE001
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.ERROR,
                summary="command-execution validator could not complete.",
                error=str(exc)[:512],
                duration_ms=int((time.time() - started) * 1000),
            )

        status = adapters.validator_status_to_technique_status(validation.status)
        evidence = {
            "path": "http-validator",
            "validator_id": _VALIDATOR_ID,
            "status": validation.status,
            "confidence": validation.confidence,
            "decision": (validation.evidence or {}).get("decision")
            or (validation.evidence or {}).get("reason"),
        }
        if status == TechniqueStatus.CONFIRMED:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.CONFIRMED,
                summary="OS command execution confirmed.",
                provides=self.provides,
                evidence=evidence,
                next_techniques=("T1082", "T1548", "T1213"),
                duration_ms=int((time.time() - started) * 1000),
            )
        return TechniqueResult(
            technique_id=self.technique_id,
            status=status,
            summary=f"command execution not confirmed ({validation.status}).",
            evidence=evidence,
            duration_ms=int((time.time() - started) * 1000),
        )
