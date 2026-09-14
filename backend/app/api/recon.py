"""Authorized synchronous reconnaissance entry point for local development."""

from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, StrictBool
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.scanning.nmap import NmapScanner
from app.scanning.nuclei import NucleiScanner
from app.scanning.scope import (
    ReconAuthorizationError,
    ReconScopeError,
    TargetVerificationRequiredError,
)
from app.scanning.tool_runner import ScannerToolError
from app.presentation import decorate_pipeline_response
from app.services.recon_pipeline import ReconPipeline


router = APIRouter(prefix="/api/scans", tags=["reconnaissance"])


class ReconScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: AnyHttpUrl
    authorized: StrictBool


def _configured_pipeline() -> ReconPipeline:
    nmap_path = os.getenv("RECON_NMAP_PATH")
    nuclei_path = os.getenv("RECON_NUCLEI_PATH")
    return ReconPipeline(
        nmap_scanner=NmapScanner(nmap_path) if nmap_path else None,
        nuclei_scanner=NucleiScanner(nuclei_path) if nuclei_path else None,
    )


@router.post("/run")
def run_recon_scan(
    request: ReconScanRequest,
    session: Session = Depends(get_db),
    pipeline: ReconPipeline = Depends(_configured_pipeline),
) -> Dict[str, Any]:
    try:
        result = pipeline.run(
            target_url=str(request.target_url),
            authorized=request.authorized,
            session=session,
        ).to_dict()
        return decorate_pipeline_response(result, controlled_lab=False)
    except ReconAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TargetVerificationRequiredError as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "target_verification_required",
                "message": str(exc),
                "canonical_origin": exc.target.origin,
                "verification_endpoint": "/api/target-verifications",
            },
        ) from exc
    except ReconScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScannerToolError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


class SkillsScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: AnyHttpUrl
    authorized: StrictBool
    phase: str = "all"


def _to_origin(url: str) -> str:
    """Reduce a full URL (which may carry a path) to its origin."""
    from urllib.parse import urlunsplit, urlsplit

    parsed = urlsplit(str(url))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target_url must be http(s) with a host")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _scope_target(url: str):
    from urllib.parse import urlsplit

    from app.scanning.scope import normalize_origin, ReconScopeError

    try:
        return normalize_origin(_to_origin(url))
    except ReconScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


_COMMON_PORTS = (
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    9200, 27017,
)


def _probe_open_ports(host: str) -> list[int]:
    """Honest lightweight TCP-connect probe of common service ports.

    Mirrors the base-recon port discovery the skill suite was designed after —
    only ports that actually accept a connection are reported, feeding the
    selector's ``port_<n>_open`` conditions (network / web / exploit gates).
    """
    import socket
    from concurrent.futures import ThreadPoolExecutor

    def check(port: int) -> int | None:
        try:
            with socket.create_connection((host, port), timeout=0.9):
                return port
        except Exception:  # noqa: BLE001
            return None

    with ThreadPoolExecutor(max_workers=16) as pool:
        found = [p for p in pool.map(check, _COMMON_PORTS) if p]
    return sorted(found)


@router.post("/skills")
def run_skills_scan(
    request: SkillsScanRequest,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Run the synced skill suite against a loopback dev target and return
    validated canonical findings (skills propose, validator decides)."""
    from uuid import uuid4

    from app.scanning.http_discovery import ScopedReconHttpClient
    from app.scanning.scope import is_loopback_host, normalize_origin
    from app.services.skills_execution import run_skills_phase
    from skills.base import SkillContext
    from app.db.models import FindingORM
    from app.core.config import settings

    if request.authorized is not True:
        raise HTTPException(status_code=403, detail="explicit authorization confirmation is required")

    try:
        target = _scope_target(str(request.target_url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if settings.AUTHORIZATION_RESTRICTED and not is_loopback_host(target.hostname):
        raise HTTPException(
            status_code=403,
            detail="skills scan is limited to loopback dev targets",
        )

    scan_id = f"skills-{uuid4()}"
    ctx = SkillContext(
        target_url=target.origin,
        host=target.hostname,
        ip=target.resolved_addresses[0] if target.resolved_addresses else None,
        port=target.port,
        scheme=target.scheme,
        scan_id=scan_id,
        authorized=True,
    )
    # Base-recon seed: honest TCP-connect probe of the common service ports
    # (the skill selector's port_*_open gates are driven by real connections,
    # never synthetic conditions), plus the probed origin path and any stack
    # banners leaked on "/".
    for port in _probe_open_ports(target.hostname) or [target.port]:
        if port not in ctx.open_ports:
            ctx.open_ports.append(port)
    ctx.discovered_paths.append("/")
    with ScopedReconHttpClient(target) as client:
        try:
            response = client.get("/")
            for name, value in response.headers.items():
                lowered = name.lower()
                if lowered == "server" or lowered == "x-powered-by":
                    ctx.technologies.append(value)
        except Exception:
            pass
        outcome = run_skills_phase(
            ctx,
            phase=request.phase,
            run_validators=True,
            dispatch_session=client,
        )

    from app.db.repository import PersistenceRepository
    from dataclasses import replace
    from sqlalchemy.exc import IntegrityError

    repository = PersistenceRepository(session)
    repository.create_scan(
        scan_id=scan_id,
        target_url=target.origin,
        authorized=True,
    )
    session.commit()
    repository = PersistenceRepository(session)
    asset_id = f"asset-{scan_id}"
    repository.persist_asset(
        scan_id=scan_id,
        asset_id=asset_id,
        hostname=ctx.host,
        base_url=target.origin,
    )
    session.commit()
    repository = PersistenceRepository(session)
    for finding in outcome.validated:
        persisted = replace(finding, asset_id=asset_id)
        if session.get(FindingORM, persisted.finding_id) is not None:
            continue
        try:
            repository.persist_finding(persisted)
        except IntegrityError:
            session.rollback()
            repository = PersistenceRepository(session)
    session.commit()

    return {
        "scan_id": scan_id,
        "target_url": target.origin,
        "phase": request.phase,
        **outcome.to_dict(),
    }
