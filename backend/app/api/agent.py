"""Live endpoint for the full LLM-driven agent loop (AgentRunService)."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.orm import Session

from app.agent.llm_client import LLMClientConfig, LLMClientError, OpenAICompatibleClient
from app.agent.llm_planner import LLMPlanner
from app.agent.models import AgentState, ABSOLUTE_MAX_AGENT_STEPS
from app.agent.run_service import AgentRunService
from app.agent.tools import AgentToolRegistry
from app.db.session import get_db
from app.db.repository import PersistenceRepository
from app.db.serialization import finding_orm_to_model
from app.models.finding import ValidationStatus

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

    # Derive asset_id and target from first finding if not explicitly given
    asset_id = request.asset_id or (findings[0].asset_id if findings else "")
    target = findings[0].target if findings else ""

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

    return result.to_dict()


@router.get("/tools")
def list_tools() -> Dict[str, Any]:
    """Return the registered agent tool catalog."""
    registry = AgentToolRegistry()
    return {"tools": [tool.to_dict() for tool in registry.list_tools()]}
