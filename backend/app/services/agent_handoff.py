"""Recon → exploit automatic handoff.

After a full-scan job completes, this service creates an exploit session bound
to the finished scan and auto-triggers the LLM agent against the scan's
eligible findings — so the operator no longer has to open /exploit, create a
session, and start the agent by hand.

Every stage is idempotent and gated on persisted facts:

  - only scans that actually completed and persisted findings are candidate
  - a session is created for a scan at most once (stable ``auto-`` name)
  - findings must be confirmed/manual_review (mirrors /api/agent/run)
  - the agent run reuses the operator authorization granted for the scan job

When the LLM endpoint is not configured the session is still created (status
``pending``) so the operator can take over in the exploit console with the
deterministic planner; the automatic agent step is simply skipped.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.agent.llm_client import (
    LLMClientConfig,
    LLMClientError,
    OpenAICompatibleClient,
)
from app.agent.llm_planner import LLMPlanner
from app.agent.models import ABSOLUTE_MAX_AGENT_STEPS, AgentState
from app.agent.run_service import AgentRunService
from app.agent.tools import AgentToolRegistry
from app.db.repository import PersistenceRepository
from app.db.serialization import finding_orm_to_model
from app.models.finding import ValidationStatus
from app.services.agent_persistence import persist_agent_run_results

logger = logging.getLogger(__name__)

_AUTO_SESSION_PREFIX = "auto-"
_ELIGIBLE_STATUSES = frozenset(
    {ValidationStatus.CONFIRMED, ValidationStatus.MANUAL_REVIEW}
)


def handoff_session_name(scan_id: str) -> str:
    """Stable session name so one scan only ever has one auto session."""
    return f"{_AUTO_SESSION_PREFIX}{scan_id[:16]}"


def _load_llm_client() -> Optional[OpenAICompatibleClient]:
    try:
        return OpenAICompatibleClient(LLMClientConfig.from_environment())
    except LLMClientError:
        return None


def auto_handoff_completed_scan(
    session: Session,
    *,
    scan_id: str,
    maximum_steps: int = 5,
    authorized: bool = True,
) -> Dict[str, Any]:
    """Auto-create an exploit session for a completed scan and run the agent.

    Returns a typed handoff report:

      status:  "completed" | "skipped" | "error"
      reason:  why a run was skipped (scan_not_found / no eligible findings /
               llm_not_configured / session_exists)
      session_id: the auto session (may be pre-existing)
    """
    repository = PersistenceRepository(session)

    scan = repository.get_scan(scan_id)
    if scan is None:
        return {
            "status": "skipped",
            "reason": "scan_not_found",
            "scan_id": scan_id,
            "session_id": None,
            "message": "scan no longer exists; nothing to hand off",
        }

    # Idempotency: at most one auto session per scan. A second completion of the
    # same scan must not fire a second agent loop.
    existing = [
        record
        for record in repository.list_exploit_sessions(scan_id=scan_id)
        if record.session_name == handoff_session_name(scan_id)
    ]
    if existing:
        return {
            "status": "skipped",
            "reason": "session_exists",
            "scan_id": scan_id,
            "session_id": existing[-1].id,
            "message": "auto exploit session already exists for this scan",
        }

    # Eligibility gate: only confirmed/manual-review findings hand off.
    findings_orm = [
        record
        for record in repository.list_findings_for_scan(scan_id)
        if record.status in _ELIGIBLE_STATUSES
    ]
    if not findings_orm:
        return {
            "status": "skipped",
            "reason": "no_eligible_findings",
            "scan_id": scan_id,
            "session_id": None,
            "message": "no eligible findings to exploit on this scan",
        }

    findings = []
    for record in findings_orm:
        try:
            findings.append(finding_orm_to_model(record))
        except Exception:  # noqa: BLE001
            logger.debug("skipping unconvertible finding %s", record.id, exc_info=True)
    if not findings:
        return {
            "status": "skipped",
            "reason": "finding_conversion_failed",
            "scan_id": scan_id,
            "session_id": None,
            "message": "none of the eligible findings could be converted",
        }

    # Create the auto exploit session bound to the completed scan.
    session_id = f"auto-{uuid.uuid4()}"
    session_row = repository.create_exploit_session(
        session_id=session_id,
        scan_id=scan_id,
        target_url=scan.target_url,
        session_name=handoff_session_name(scan_id),
        tool_used="agent-llm-loop",
        status="running",
    )
    session.flush()

    client = _load_llm_client()
    if client is None:
        session_row.status = "pending"
        session.commit()
        return {
            "status": "skipped",
            "reason": "llm_not_configured",
            "scan_id": scan_id,
            "session_id": session_id,
            "message": (
                "exploit session created, but AGENT_LLM_BASE_URL is not configured "
                "- automatic agent run skipped"
            ),
        }

    asset_id = findings[0].asset_id or ""
    scan_target = scan.target_url or (findings[0].target or "")
    try:
        from app.scanning.scope import normalize_origin

        target = normalize_origin(scan_target).origin
    except Exception:  # noqa: BLE001
        session_row.status = "failed"
        session.commit()
        return {
            "status": "error",
            "reason": "invalid_target",
            "scan_id": scan_id,
            "session_id": session_id,
            "error": f"scan target is not a valid HTTP origin: {scan_target}",
        }

    def _same_origin(value: str) -> bool:
        try:
            return normalize_origin(value).origin == target
        except Exception:  # noqa: BLE001
            return False

    findings = [finding for finding in findings if _same_origin(finding.target or "")]

    if not findings:
        session_row.status = "pending"
        session.commit()
        return {
            "status": "skipped",
            "reason": "no_in_scope_findings",
            "scan_id": scan_id,
            "session_id": session_id,
            "message": "eligible findings were outside the scan origin",
        }

    try:
        bounded_steps = max(1, min(int(maximum_steps), ABSOLUTE_MAX_AGENT_STEPS))
        initial_state = AgentState.from_findings(
            scan_id=scan_id,
            target=target,
            asset_id=asset_id,
            authorized=authorized,
            findings=findings,
            maximum_steps=bounded_steps,
        )
    except Exception as exc:  # noqa: BLE001
        session_row.status = "failed"
        session.commit()
        return {
            "status": "error",
            "reason": "state_build_failed",
            "scan_id": scan_id,
            "session_id": session_id,
            "error": str(exc),
        }

    service = AgentRunService(LLMPlanner(client), registry=AgentToolRegistry())
    try:
        result = service.run(initial_state, session=session)
    except Exception as exc:  # noqa: BLE001
        logger.exception("auto agent run failed for scan %s", scan_id)
        session_row.status = "failed"
        session.commit()
        return {
            "status": "error",
            "reason": "agent_run_failed",
            "scan_id": scan_id,
            "session_id": session_id,
            "error": str(exc) or exc.__class__.__name__,
        }

    persist_summary = persist_agent_run_results(
        session,
        scan_id=scan_id,
        result=result,
        session_id=session_id,
        session_name=handoff_session_name(scan_id),
        target_url=scan.target_url,
    )

    return {
        "status": persist_summary["status"],
        "reason": "agent_run",
        "scan_id": scan_id,
        "session_id": session_id,
        "message": "automatic agent run finished",
        "agent_status": result.status,
        "stop_reason": result.stop_reason,
        "steps_used": result.steps_used,
        "final_capabilities": list(result.final_state.capabilities),
        "mitre_techniques": list(result.final_state.mitre_techniques),
        "persisted": persist_summary,
    }


__all__ = ["auto_handoff_completed_scan", "handoff_session_name"]