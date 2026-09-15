"""API endpoints for version-CVE resolution, privilege escalation mapping, and retesting."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.db.repository import PersistenceNotFoundError, PersistenceRepository
from app.db.session import get_db
from app.services.privilege_escalation import (
    build_privilege_escalation_map,
)
from app.services.retesting import (
    RetestError,
    retest_findings_batch,
    retest_finding,
)
from app.services.version_cve_resolver import (
    batch_resolve_versions,
    resolve_version_to_cves,
)


router = APIRouter(prefix="/api/security", tags=["security"])


# ── Version → CVE Resolution ──────────────────────────────────────────

class VersionResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product: str
    version: str
    use_nvd_api: bool = True


class BatchVersionResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    services: List[Dict[str, str]]
    use_nvd_api: bool = True


@router.post("/cve/resolve")
def resolve_cves(
    request: VersionResolveRequest,
) -> Dict[str, Any]:
    """Resolve a single product/version to known CVEs with CVSS scoring."""
    result = resolve_version_to_cves(
        request.product,
        request.version,
        use_nvd_api=request.use_nvd_api,
    )
    return result.to_dict()


@router.post("/cve/batch")
def batch_resolve_cves(
    request: BatchVersionResolveRequest,
) -> Dict[str, Any]:
    """Resolve multiple product/version pairs to CVEs."""
    results = batch_resolve_versions(
        request.services,
        use_nvd_api=request.use_nvd_api,
    )
    return {
        "results": [r.to_dict() for r in results],
        "total_services": len(results),
        "total_cves_found": sum(r.total_cves for r in results),
    }


# ── Privilege Escalation Depth Map ────────────────────────────────────

@router.get("/escalation-map/{scan_id}/{asset_id}")
def get_escalation_map(
    scan_id: str,
    asset_id: str,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get the privilege escalation depth map for a scan/asset."""
    repository = PersistenceRepository(session)
    findings = repository.list_findings_for_scan(scan_id)

    asset_findings = [f for f in findings if f.asset_id == asset_id]
    if not asset_findings:
        raise HTTPException(
            status_code=404,
            detail=f"no findings found for scan {scan_id!r}, asset {asset_id!r}",
        )

    escalation_map = build_privilege_escalation_map(
        scan_id=scan_id,
        asset_id=asset_id,
        findings=asset_findings,
    )
    return escalation_map.to_dict()


@router.get("/escalation-map/{scan_id}")
def get_scan_escalation_maps(
    scan_id: str,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get privilege escalation maps for all assets in a scan."""
    repository = PersistenceRepository(session)
    scan = repository.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"scan {scan_id!r} not found")

    findings = repository.list_findings_for_scan(scan_id)
    asset_ids = {f.asset_id for f in findings if f.asset_id}

    maps = []
    for aid in asset_ids:
        asset_findings = [f for f in findings if f.asset_id == aid]
        if asset_findings:
            emap = build_privilege_escalation_map(
                scan_id=scan_id,
                asset_id=aid,
                findings=asset_findings,
            )
            maps.append(emap.to_dict())

    return {
        "scan_id": scan_id,
        "total_assets": len(maps),
        "maps": maps,
    }


# ── Retesting ─────────────────────────────────────────────────────────

class RetestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    finding_ids: Optional[List[str]] = None
    only_confirmed: bool = False


class SingleRetestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    finding_id: str


@router.post("/retest")
def retest_findings(
    request: RetestRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retest findings to verify remediation."""
    try:
        results = retest_findings_batch(
            session,
            scan_id=request.scan_id,
            finding_ids=request.finding_ids,
            only_confirmed=request.only_confirmed,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"retesting failed: {exc}",
        )

    return {
        "scan_id": request.scan_id,
        "total_retested": len(results),
        "results": [r.to_dict() for r in results],
    }


@router.post("/retest/single")
def retest_single_finding(
    request: SingleRetestRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retest a single finding."""
    try:
        result = retest_finding(
            session,
            scan_id=request.scan_id,
            finding_id=request.finding_id,
        )
    except RetestError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"retesting failed: {exc}",
        )

    return result.to_dict()
