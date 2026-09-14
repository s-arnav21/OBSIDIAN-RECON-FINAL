"""Unified recon -> exploit API on the attack database.

Exploitation consumes persisted recon findings, plans the attack against the
MITRE ATT&CK technique resolved at recon time (LLM-driven with a deterministic
fallback), and performs the attempt through the registered canonical validator.
The operator must confirm each attempt with ``authorized: true``.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy.orm import Session

from app.attack_chain.mitre_mapping import TECHNIQUE_DEFINITIONS
from app.db.repository import PersistenceRepository, PersistenceNotFoundError
from app.db.serialization import (
    exploit_session_to_dict,
    exploit_to_dict,
)
from app.db.session import get_db
from app.models.finding import ValidationStatus
from app.services.exploit_planner import (
    build_exploit_plan,
    load_llm_client,
)
from app.services.attack_execution import execute_planned_attack
from app.services.exploitation import (
    ExploitationError,
    close_exploit_session,
    create_exploit_session,
    register_shell,
)


router = APIRouter(prefix="/api/attacks", tags=["attacks"])

_ELIGIBLE_STATUSES = frozenset({
    ValidationStatus.CONFIRMED,
    ValidationStatus.MANUAL_REVIEW,
})


class SessionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    session_name: str
    tool_used: Optional[str] = None


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str


class ExploitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    authorized: StrictBool


class ShellRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shell_type: str
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    active: bool = False


@router.get("/ttp")
def list_ttp_catalog() -> Dict[str, Any]:
    return {
        "techniques": [
            {
                "technique_id": technique.technique_id,
                "technique_name": technique.technique_name,
                "tactic": technique.tactic,
                "description": technique.description,
                "vulnerability_types": list(technique.vulnerability_types),
                "provides": list(technique.provides),
            }
            for technique in TECHNIQUE_DEFINITIONS.values()
        ]
    }


@router.get("/sessions")
def list_attack_sessions(
    scan_id: Optional[str] = None,
    session: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    repository = PersistenceRepository(session)
    return [
        exploit_session_to_dict(record)
        for record in repository.list_exploit_sessions(scan_id=scan_id)
    ]


@router.post("/sessions")
def create_attack_session(
    request: SessionCreateRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        return create_exploit_session(
            session,
            scan_id=request.scan_id,
            session_name=request.session_name,
            tool_used=request.tool_used,
        )
    except PersistenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ExploitationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/sessions/{session_id}")
def get_attack_session(
    session_id: str,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    repository = PersistenceRepository(session)
    record = repository.get_exploit_session(session_id)
    if record is None:
        raise HTTPException(status_code=404, detail="attack session not found")
    return exploit_session_to_dict(record)


def _load_finding(session: Session, scan_id: str, finding_id: str):
    repository = PersistenceRepository(session)
    for candidate in repository.list_findings_for_scan(scan_id):
        if candidate.id == finding_id:
            return candidate
    raise HTTPException(
        status_code=404,
        detail=f"finding {finding_id!r} not found on scan {scan_id!r}",
    )


@router.post("/sessions/{session_id}/plan")
def plan_attack(
    session_id: str,
    request: PlanRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Preview the exploitation plan for one finding without running anything."""
    repository = PersistenceRepository(session)
    attack_session = repository.get_exploit_session(session_id)
    if attack_session is None:
        raise HTTPException(status_code=404, detail="attack session not found")

    finding = _load_finding(session, attack_session.scan_id, request.finding_id)
    if finding.status not in _ELIGIBLE_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"finding {finding.id!r} is {finding.status!r}; only "
                f"{sorted(_ELIGIBLE_STATUSES)} findings are eligible"
            ),
        )

    plan = build_exploit_plan(finding, client=load_llm_client())
    return {
        "finding_id": finding.id,
        "vulnerability_type": finding.vulnerability_type,
        "endpoint": finding.endpoint,
        "status": finding.status,
        "plan": plan.to_dict(),
    }


@router.post("/sessions/{session_id}/exploits")
def run_attack(
    session_id: str,
    request: ExploitRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Confirm the operator decision and execute the planned exploitation."""
    if request.authorized is not True:
        raise HTTPException(
            status_code=403,
            detail="exploitation requires explicit operator authorization",
        )

    repository = PersistenceRepository(session)
    attack_session = repository.get_exploit_session(session_id)
    if attack_session is None:
        raise HTTPException(status_code=404, detail="attack session not found")
    if attack_session.status == "completed":
        raise HTTPException(
            status_code=409,
            detail="attack session is already completed",
        )

    finding = _load_finding(session, attack_session.scan_id, request.finding_id)
    if finding.status not in _ELIGIBLE_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"finding {finding.id!r} is {finding.status!r}; only "
                f"{sorted(_ELIGIBLE_STATUSES)} findings are eligible"
            ),
        )

    plan = build_exploit_plan(finding, client=load_llm_client())
    attempt = execute_planned_attack(plan, finding)

    attempt_status = (attempt or {}).get("status")
    if attempt_status in {None, "", "planned"}:
        outcome = "planned"
    elif attempt_status in {
        "success",
        ValidationStatus.CONFIRMED,
    }:
        outcome = "success"
    elif attempt_status in {
        "failed",
        ValidationStatus.REJECTED,
    }:
        outcome = "failed"
    elif attempt_status == "error":
        outcome = "error"
    else:
        outcome = "inconclusive"

    module_name = (
        (plan.tooling[0] if plan.tooling else None)
        or (plan.technique_id if plan.technique_id != "UNMAPPED" else None)
        or f"{finding.vulnerability_type}-exploit"
    )
    output = json.dumps(
        {
            "plan": plan.to_dict(),
            "attempt": {
                "status": (attempt or {}).get("status"),
                "method": (attempt or {}).get("method"),
                "exit_code": (attempt or {}).get("exit_code"),
                "stdout": (attempt or {}).get("stdout", ""),
                "stderr": (attempt or {}).get("stderr", ""),
                "decision": (attempt or {}).get("decision", ""),
            },
        },
        indent=2,
    )[:250000]

    exploit = repository.persist_exploit(
        exploit_id=f"exp-attempt-{uuid4()}",
        session_id=session_id,
        finding_id=finding.id,
        technique_id=plan.technique_id if plan.technique_id != "UNMAPPED" else None,
        module_name=module_name,
        description=(
            f"Operator-authorized exploit of {finding.vulnerability_type} on "
            f"{finding.endpoint or finding.target}; technique {plan.technique_id}"
        ),
        outcome=outcome,
        output=output,
    )

    if attack_session.status == "pending":
        repository.update_exploit_session_status(session_id, "running")
    if outcome == "success":
        repository.update_exploit_session_status(session_id, "exploited")
    session.commit()
    session.refresh(exploit)
    session.refresh(attack_session)

    return {
        "session": exploit_session_to_dict(attack_session),
        "plan": plan.to_dict(),
        "attempt": attempt,
        "exploit": exploit_to_dict(exploit),
    }


@router.post("/sessions/{session_id}/shells")
def register_attack_shell(
    session_id: str,
    request: ShellRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        return register_shell(
            session,
            session_id=session_id,
            shell_type=request.shell_type,
            host=request.host,
            port=request.port,
            username=request.username,
            password=request.password,
            active=request.active,
        )
    except PersistenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ExploitationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/sessions/{session_id}/close")
def close_attack_session(
    session_id: str,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        return close_exploit_session(session, session_id=session_id)
    except PersistenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ExploitationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc