"""Persistence of one agent run into scan-bound database records.

A completed agent run produces two kinds of outputs that must survive the API
call and be auditable from the scan's exploit session:

  - an exploit record per step (existing behaviour; JSON observation blob)
  - structured validation evidence (``validations`` + ``evidence`` rows) and a
    status update on the finding the agent actually validated

Everything is written in a single transaction so the caller either sees the
full run or an explicit failure -- never a silent partial write.  The same
function drives the live ``/api/agent/run`` endpoint and the automatic
recon-to-exploit handoff so agent persistence is defined exactly once.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.agent.models import AgentStatus
from app.agent.run_service import AgentRunResult
from app.db.models import ExploitSessionORM, FindingORM
from app.db.repository import PersistenceRepository, PersistenceNotFoundError
from app.models.finding import Finding

logger = logging.getLogger(__name__)

_AGENT_SESSION_TOOL = "agent-llm-loop"
# Default session name used by the ad-hoc /api/agent/run endpoint.
_RUN_SESSION_PREFIX = "agent-run-"


def agent_run_session_name(scan_id: str) -> str:
    """Stable name so repeated ad-hoc runs reuse one audit session per scan."""
    return f"{_RUN_SESSION_PREFIX}{scan_id[:16]}"


def _persist_step_exploit(
    repository: PersistenceRepository,
    *,
    session_id: str,
    step: Any,
) -> None:
    observation = step.observation
    action = step.proposed_action
    finding_id = action.finding_id or ""

    output_data = {
        "step_number": step.step_number,
        "tool_id": action.tool_id,
        "finding_id": action.finding_id,
        "reason": action.reason,
        "execution_status": observation.execution_status,
        "summary": observation.summary,
        "validation_status": observation.validation_status,
        "error_category": observation.error_category,
        "policy_code": step.policy_decision.code,
        "policy_reason": step.policy_decision.reason,
    }

    outcome = (
        "success"
        if observation.execution_status == "completed"
        else "failed" if observation.execution_status == "failed" else "inconclusive"
    )

    if (
        finding_id
        and repository.session.get(FindingORM, finding_id) is None
    ):
        finding_id = ""

    repository.persist_exploit(
        exploit_id=f"agent-exp-{uuid.uuid4()}",
        session_id=session_id,
        finding_id=finding_id if finding_id else None,
        technique_id=None,
        module_name=f"agent:{action.tool_id}",
        description=(
            f"Agent step {step.step_number}: {action.tool_id} "
            f"via {action.tool_id} - {outcome}"
        ),
        outcome=outcome,
        output=json.dumps(output_data, default=str)[:250000],
    )


def _parse_connection(value: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """Split a bounded ``host:port`` connection string into its parts."""
    if not value or ":" not in value:
        return (value or None), None
    host, _, port_text = value.rpartition(":")
    if not host:
        return value, None
    try:
        port = int(port_text)
    except ValueError:
        return value, None
    if not 1 <= port <= 65535:
        return value, None
    return host, port


def _persist_step_shell(
    repository: PersistenceRepository,
    *,
    session_id: str,
    step: Any,
) -> Optional[dict]:
    """Persist a shell row when the step's tool reported one was obtained.

    The metasploit tools surface an obtained meterpreter session through the
    observation's bounded ``shell_info`` metadata.  Writing it to the unified
    ``shells`` table makes the acquisition auditable from the exploit session
    and removes the manual POST endpoint from being the only way a shell is
    ever recorded.
    """
    observation = step.observation
    if not observation.shell_obtained:
        return None
    if observation.execution_status != "completed":
        return None
    if not step.policy_decision.allowed:
        return None

    info = (
        dict(observation.shell_info)
        if isinstance(observation.shell_info, dict)
        else {}
    )
    shell_type = str(info.get("type") or "meterpreter")[:64]
    host, port = _parse_connection(info.get("connection"))

    for existing in repository.list_shells_for_session(session_id):
        if (
            existing.shell_type == shell_type
            and existing.host == host
            and existing.port == port
        ):
            return None

    record = repository.persist_shell(
        shell_id=f"agent-shell-{uuid.uuid4()}",
        session_id=session_id,
        shell_type=shell_type,
        host=host,
        port=port,
        active=True,
    )
    return {
        "id": record.id,
        "shell_type": record.shell_type,
        "host": record.host,
        "port": record.port,
    }


def _persist_validation_evidence(
    repository: PersistenceRepository,
    *,
    finding_id: str,
    result: Any,
) -> bool:
    """Write structured validation + evidence rows for one validated finding."""
    validation = repository.persist_validation(
        finding_id=finding_id,
        result=result,
    )
    repository.persist_evidence(
        validation_id=validation.id,
        finding_id=finding_id,
        evidence_type="validation_result",
        evidence_json=dict(result.evidence),
    )
    return True


def _persist_finding_status(
    repository: PersistenceRepository,
    *,
    finding_id: str,
    finding: Finding,
) -> bool:
    """Propagate the agent-observed validation status back to the finding."""
    try:
        repository.update_finding_validation_status(
            finding_id,
            finding.validation_status,
        )
    except (PersistenceNotFoundError, ValueError):
        logger.debug(
            "skipping status update for finding %s (not in this database)",
            finding_id,
            exc_info=True,
        )
        return False
    return True


def _load_or_create_session(
    repository: PersistenceRepository,
    *,
    scan_id: str,
    session_id: Optional[str],
    session_name: Optional[str],
    target_url: str,
) -> ExploitSessionORM:
    """Resolve the exploit session for a run, creating one when needed."""
    resolved_name = session_name or agent_run_session_name(scan_id)
    if session_id is not None:
        existing = repository.get_exploit_session(session_id)
        if existing is not None:
            return existing
        return repository.create_exploit_session(
            session_id=session_id,
            scan_id=scan_id,
            target_url=target_url,
            session_name=resolved_name,
            tool_used=_AGENT_SESSION_TOOL,
            status="running",
        )

    for record in repository.list_exploit_sessions(scan_id=scan_id):
        if record.session_name == resolved_name:
            return record
    return repository.create_exploit_session(
        session_id=f"agent-{uuid.uuid4()}",
        scan_id=scan_id,
        target_url=target_url,
        session_name=resolved_name,
        tool_used=_AGENT_SESSION_TOOL,
        status="running",
    )


def persist_agent_run_results(
    session: Session,
    *,
    scan_id: str,
    result: AgentRunResult,
    session_id: Optional[str] = None,
    session_name: Optional[str] = None,
    target_url: str = "",
) -> Dict[str, Any]:
    """Persist one completed agent run and return a short audit summary.

    ``session_id``/``session_name`` are only used when the caller has already
    reserved an exploit session (the automatic handoff path).  Without them the
    run reuses or creates the scan's ``agent-run`` session.
    """
    repository = PersistenceRepository(session)
    run_session = _load_or_create_session(
        repository,
        scan_id=scan_id,
        session_id=session_id,
        session_name=session_name,
        target_url=target_url,
    )
    session.flush()

    step_count = 0
    validation_count = 0
    findings_updated = 0
    incompatible_statuses = 0
    shell_count = 0
    for step in result.steps:
        _persist_step_exploit(
            repository,
            session_id=run_session.id,
            step=step,
        )
        step_count += 1

        if _persist_step_shell(
            repository,
            session_id=run_session.id,
            step=step,
        ) is not None:
            shell_count += 1

        finding_id = step.proposed_action.finding_id or ""
        if not step.validation_result or not finding_id:
            continue

        try:
            if _persist_validation_evidence(
                repository,
                finding_id=finding_id,
                result=step.validation_result,
            ):
                validation_count += 1
        except PersistenceNotFoundError:
            # Finding was removed concurrently; its audit trail is skipped
            # rather than failing the whole agent run.
            logger.debug(
                "skipping validation evidence for missing finding %s",
                finding_id,
                exc_info=True,
            )

        if step.updated_finding is None:
            continue
        if _persist_finding_status(
            repository,
            finding_id=finding_id,
            finding=step.updated_finding,
        ):
            findings_updated += 1
        else:
            incompatible_statuses += 1

    final_status = (
        "completed" if result.status == AgentStatus.COMPLETED else "failed"
    )
    repository.update_exploit_session_status(run_session.id, final_status)
    session.commit()

    return {
        "session_id": run_session.id,
        "status": final_status,
        "steps": step_count,
        "validations": validation_count,
        "findings_updated": findings_updated,
        "findings_skipped": incompatible_statuses,
        "shells": shell_count,
    }


__all__ = ["persist_agent_run_results", "agent_run_session_name"]