"""Minimal persistence API for frontend scan-result retrieval."""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, StrictBool
from sqlalchemy.orm import Session

from app.db.repository import PersistenceRepository
from app.db.serialization import (
    attack_chain_to_dict,
    finding_to_dict,
    scan_to_dict,
)
from app.db.session import get_db


router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: AnyHttpUrl
    authorized: StrictBool


def _require_scan(repository: PersistenceRepository, scan_id: str) -> None:
    if repository.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="scan not found")


@router.post("")
def create_scan(
    request: ScanCreateRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    repository = PersistenceRepository(session)
    try:
        scan = repository.create_scan(
            target_url=str(request.target_url),
            authorized=request.authorized,
        )
        session.commit()
        session.refresh(scan)
    except Exception:
        session.rollback()
        raise
    return scan_to_dict(scan)


@router.get("")
def list_scans(
    limit: int = 25,
    session: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    repository = PersistenceRepository(session)
    bounded_limit = max(1, min(limit, 200))
    return [
        scan_to_dict(scan)
        for scan in repository.list_scans(limit=bounded_limit)
    ]


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    repository = PersistenceRepository(session)
    scan = repository.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan_to_dict(scan)


@router.get("/{scan_id}/findings")
def list_scan_findings(
    scan_id: str,
    session: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    repository = PersistenceRepository(session)
    _require_scan(repository, scan_id)
    return [
        finding_to_dict(finding)
        for finding in repository.list_findings_for_scan(scan_id)
    ]


@router.get("/{scan_id}/chains")
def list_scan_chains(
    scan_id: str,
    session: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    repository = PersistenceRepository(session)
    _require_scan(repository, scan_id)
    return [
        attack_chain_to_dict(chain)
        for chain in repository.list_attack_chains_for_scan(scan_id)
    ]
