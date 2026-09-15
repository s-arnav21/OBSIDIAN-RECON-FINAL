"""Live endpoint for the full LLM-driven agent loop (AgentRunService)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.orm import Session

from app.agent.llm_client import LLMClientConfig, LLMClientError, OpenAICompatibleClient
from app.agent.llm_planner import LLMPlanner
from app.agent.models import AgentState, ABSOLUTE_MAX_AGENT_STEPS
from app.agent.run_service import AgentRunService
from app.agent.tools import AgentToolRegistry
from app.db.models import EvidenceORM, ExploitORM, ExploitSessionORM, ValidationORM
from app.db.session import get_db
from app.db.repository import PersistenceRepository
from app.db.serialization import finding_orm_to_model
from app.models.finding import ValidationStatus
from app.scanning.scope import normalize_origin
from uuid import uuid4

router = APIRouter(prefix="/api/agent", tags=["agent"])


class AgentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    asset_id: str
    finding_ids: List[str] = Field(default_factory=list)
    maximum_steps: int = Field(default=5, ge=1, le=ABSOLUTE_MAX_AGENT_STEPS)
    authorized: StrictBool = False


def _load_llm_client() -> Optional[OpenAICompatibleClient]:
    try:
        config = LLMClientConfig.from_environment()
        return OpenAICompatibleClient(config)
    except LLMClientError:
        return None


def _build_service() -> AgentRunService:
    client = _load_llm_client()
    if client is None:
        raise HTTPException(
            status_code=503,
            detail="LLM endpoint is not configured. Set AGENT_LLM_BASE_URL in .env.",
        )
    registry = AgentToolRegistry()
    planner = LLMPlanner(client)
    return AgentRunService(planner, registry=registry)


@router.post("/run")
def run_agent(
    request: AgentRunRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Run the full LLM-orchestrated agent loop against a set of findings.

    The LLM selects one registered tool per step; the policy gate and
    deterministic validators decide whether the action is permitted and
    what the outcome is. The LLM never crafts payloads directly.
    """
    if request.authorized is not True:
        raise HTTPException(
            status_code=403,
            detail="agent run requires explicit operator authorization",
        )

    repository = PersistenceRepository(session)

    # Load and validate scan
    scan = repository.get_scan(request.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")

    # Load findings — either the requested subset or all eligible ones
    all_findings_orm = repository.list_findings_for_scan(request.scan_id)
    eligible_statuses = {ValidationStatus.CONFIRMED, ValidationStatus.MANUAL_REVIEW}

    if request.finding_ids:
        findings_orm = [
            f for f in all_findings_orm
            if f.id in request.finding_ids and f.status in eligible_statuses
        ]
        missing = set(request.finding_ids) - {f.id for f in findings_orm}
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"findings not found or not eligible: {sorted(missing)}",
            )
    else:
        findings_orm = [
            f for f in all_findings_orm if f.status in eligible_statuses
        ][:ABSOLUTE_MAX_AGENT_STEPS * 2]

    if not findings_orm:
        raise HTTPException(
            status_code=422,
            detail="no eligible findings (confirmed or manual_review) for this scan",
        )

    # Convert ORM findings to canonical Finding models
    findings = []
    for f_orm in findings_orm:
        try:
            findings.append(finding_orm_to_model(f_orm))
        except Exception:
            continue

    if not findings:
        raise HTTPException(
            status_code=422,
            detail="could not convert any findings to agent-compatible models",
        )

    # Derive asset_id and target from the scan's canonical origin, then keep
    # only the findings that belong to that exact origin.
    asset_id = request.asset_id or (findings[0].asset_id if findings else "")
    scan_target = scan.target_url or (findings[0].target if findings else "")
    try:
        target = normalize_origin(scan_target).origin
    except Exception:
        raise HTTPException(
            status_code=422,
            detail=f"scan target is not a valid HTTP origin: {scan_target}",
        )

    def _same_origin(value: str) -> bool:
        try:
            return normalize_origin(value).origin == target
        except Exception:
            return False

    findings = [f for f in findings if _same_origin(f.target or "")]

    # Build initial agent state
    try:
        initial_state = AgentState.from_findings(
            scan_id=request.scan_id,
            target=target,
            asset_id=asset_id,
            authorized=request.authorized,
            findings=findings,
            maximum_steps=request.maximum_steps,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"could not build agent state: {exc}",
        )

    # Build and run the agent
    try:
        service = _build_service()
    except HTTPException:
        raise

    try:
        result = service.run(initial_state, session=session)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"agent run failed: {exc}",
        )

    # Persist agent run results to the database
    try:
        _persist_agent_results(session, request.scan_id, request.asset_id, result)
    except Exception as exc:
        # Log but don't fail the request - results are still returned
        import logging
        logging.getLogger(__name__).warning(
            "Failed to persist agent results: %s", exc,
        )

    return result.to_dict()


def _persist_agent_results(
    session: Session,
    scan_id: str,
    asset_id: str,
    result: "AgentRunResult",
) -> None:
    """Persist agent run results: exploit attempts and validation evidence."""
    from app.agent.run_service import AgentRunResult

    repository = PersistenceRepository(session)

    # Find or create an exploit session for the agent run
    agent_session_name = f"agent-run-{scan_id[:16]}"
    existing_sessions = repository.list_exploit_sessions(scan_id=scan_id)
    agent_session = None
    for s in existing_sessions:
        if s.session_name == agent_session_name:
            agent_session = s
            break

    if agent_session is None:
        agent_session_record = repository.create_exploit_session(
            session_id=f"agent-{uuid4()}",
            scan_id=scan_id,
            target_url="",
            session_name=agent_session_name,
            tool_used="agent-llm-loop",
            status="running",
        )
        agent_session = agent_session_record

    # Persist each step's outcome as an exploit record
    for step in result.steps:
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

        outcome = "success" if observation.execution_status == "completed" else (
            "failed" if observation.execution_status == "failed" else "inconclusive"
        )

        repository.persist_exploit(
            exploit_id=f"agent-exp-{uuid4()}",
            session_id=agent_session.id,
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

    # Update session status
    final_status = "completed" if result.status == "done" else "failed"
    repository.update_exploit_session_status(agent_session.id, final_status)
    session.commit()


@router.get("/tools")
def list_tools() -> Dict[str, Any]:
    """Return the registered agent tool catalog."""
    registry = AgentToolRegistry()
    return {"tools": [tool.to_dict() for tool in registry.list_tools()]}
