"""T1548 — Abuse Elevation Control Mechanism.

Enumerates local privilege-escalation vectors on the target by delivering a
fixed, read-only enumeration command through the finding's command-execution
endpoint: SUID/SGID binaries, passwordless sudo, file capabilities, and
writable system paths. Confirmation (and ``local_privilege_escalation``) is
granted only when the parsed output contains at least one concrete finding —
the echoed section headers are never treated as evidence.
"""
from __future__ import annotations

import time
from typing import Optional

from app.automation import register
from app.automation import session as session_adapters
from app.automation.base import AutomationContext, TechniqueResult, TechniqueScript, TechniqueStatus
from app.automation.delivery import (
    SUID_ENUM_COMMAND,
    count_elevation_vectors,
    deliver_rce_command,
    summarize_elevation_controls,
)


@register
class AbuseElevationControl(TechniqueScript):
    """Enumerate elevation-control misconfigurations (MITRE T1548)."""

    technique_id = "T1548"
    name = "Abuse Elevation Control Mechanism"
    tactic = "Privilege Escalation"
    description = (
        "Deliver a fixed enumeration command to find SUID/SGID binaries, sudo "
        "misconfigurations, capabilities and writable system paths."
    )
    requires_any = ("command_execution",)
    provides = ("local_privilege_escalation",)
    vuln_types = ("misconfiguration", "system-information-discovery")
    allowed_options = ("endpoint", "parameter_name")
    automatic_allowed = True

    def execute(self, ctx: AutomationContext) -> TechniqueResult:
        started = time.time()
        target_session: Optional[object] = session_adapters.open_context_session(ctx)
        identity = None
        if target_session is not None:
            info = getattr(target_session, "info", None)
            identity = info.describe() if hasattr(info, "describe") else {"kind": "session"}
            try:
                run = target_session.run(  # type: ignore[attr-defined]
                    SUID_ENUM_COMMAND, timeout=min(int(ctx.timeout_seconds or 120), 180)
                )
                rc, stdout, stderr = run.rc, run.stdout, run.stderr
            except Exception as exc:  # noqa: BLE001 — fail-soft
                rc, stdout, stderr = -1, "", f"{type(exc).__name__}: {exc}"
            transport = "session"
        else:
            rc, stdout, stderr = deliver_rce_command(
                ctx, SUID_ENUM_COMMAND, timeout=ctx.timeout_seconds
            )
            transport = "rce"

        artifact = None
        from app.automation import adapters

        if stdout:
            artifact = adapters.write_artifact(ctx, "t1548_elevation.txt", stdout)
        vectors = summarize_elevation_controls(stdout)
        vector_counts = {name: len(items) for name, items in vectors.items()}
        vector_count = count_elevation_vectors(vectors)
        evidence = {
            "command": SUID_ENUM_COMMAND,
            "transport": transport,
            "session": identity,
            "return_code": rc,
            "vector_counts": vector_counts,
            "vector_count": vector_count,
            "output": stdout[:2000],
            "stderr": (stderr or "")[:512],
        }
        artifacts = (artifact,) if artifact else ()
        if stdout and vector_count > 0:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.CONFIRMED,
                summary=(
                    f"local elevation-control vectors identified "
                    f"({vector_count} finding(s))."
                ),
                provides=self.provides,
                evidence=evidence,
                artifacts=artifacts,
                next_techniques=("T1068",),
                duration_ms=int((time.time() - started) * 1000),
            )
        return TechniqueResult(
            technique_id=self.technique_id,
            status=TechniqueStatus.INCONCLUSIVE,
            summary="no elevation-control vectors confirmed from enumeration output.",
            evidence=evidence,
            artifacts=artifacts,
            duration_ms=int((time.time() - started) * 1000),
        )
