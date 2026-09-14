"""Async full-scan job API — the recon-browser flow.

POST  /api/scans/jobs                 create a background full-scan job
GET   /api/scans/jobs                 list live jobs (pruned of stale ones)
GET   /api/scans/jobs/{job_id}        poll a job (steps + streamed findings)
POST  /api/scans/jobs/{job_id}/cancel stop a running job
GET   /api/scans/profiles             named scan profiles for the UI

Jobs run the reference end-to-end pipeline (passive recon + active scan) in a
background thread and journal live steps into an in-memory ScanJob. Registering
this router BEFORE the /{scan_id} scans router keeps /jobs from colliding with
the dynamic scan-id path.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, StrictBool

from app.core.config import settings
from app.core.progress import (
    create_job,
    get_job,
    make_progress_callback,
    prune_jobs,
    seed_manifest,
)
from app.db.session import get_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["reconnaissance"])


class FullScanJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: AnyHttpUrl
    authorized: StrictBool
    name: str
    profile: Optional[str] = "webapp"
    include: Optional[list[str]] = None
    skip: Optional[list[str]] = None
    timeout: Optional[int] = None
    ports: Optional[str] = None


def _scope_target(url: str):
    from urllib.parse import urlunsplit, urlsplit

    from app.scanning.scope import ReconScopeError, normalize_origin

    parsed = urlsplit(str(url))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="target_url must be http(s) with a host")
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    try:
        return normalize_origin(origin)
    except ReconScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/profiles")
def list_profiles() -> dict:
    from app.core.profiles import PROFILES

    return {
        "profiles": [
            profile.to_dict()
            for profile in PROFILES.values()
        ]
    }


@router.post("/jobs")
def create_full_scan_job(request: FullScanJobRequest) -> dict:
    from app.scanning.scope import is_loopback_host

    if request.authorized is not True:
        raise HTTPException(status_code=403, detail="explicit authorization confirmation is required")

    target = _scope_target(str(request.target_url))
    if settings.AUTHORIZATION_RESTRICTED and not is_loopback_host(target.hostname):
        raise HTTPException(
            status_code=403,
            detail="full scan jobs are limited to loopback dev targets",
        )

    from app.core.profiles import get_profile

    profile = get_profile(request.profile)
    allow_exploit = profile.allow_exploit_skills
    if settings.ALLOW_EXPLOIT_SKILLS:
        allow_exploit = True

    target_url = target.origin
    job = create_job(target_url, name=request.name or target_url)
    seed_manifest(job, include=request.include, skip=request.skip,
                  allow_exploit=allow_exploit, profile=profile)

    _spawn_worker(job, target_url=target_url, request=request, profile=profile)
    return job.snapshot()


def _spawn_worker(job, *, target_url: str, request: FullScanJobRequest, profile) -> None:
    def worker() -> None:
        session = None
        try:
            session = get_session_factory()()
            from app.services.full_scan import run_full_scan

            result = run_full_scan(
                target_url=target_url,
                authorized=True,
                name=request.name,
                profile_name=profile.name,
                include=request.include,
                skip=request.skip,
                timeout=request.timeout,
                ports=request.ports,
                progress=make_progress_callback(job),
                cancel_event=job.cancel_event,
                persist=True,
                session=session,
            )
            job.set_result(result.to_dict())
        except Exception as exc:  # noqa: BLE001
            from pipeline._errors import ScanCancelled

            if isinstance(exc, ScanCancelled) or job.cancel_event.is_set():
                job.set_cancelled()
            else:
                logger.exception("full-scan job %s failed", job.id)
                job.set_result(None, error=str(exc) or exc.__class__.__name__)
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001
                    pass

    thread = threading.Thread(target=worker, name=f"full-scan-{job.id}", daemon=True)
    thread.start()


@router.get("/jobs")
def list_jobs() -> dict:
    from app.core.progress import _JOBS

    prune_jobs()
    snapshots = sorted(
        (job.snapshot() for job in list(_JOBS.values())),
        key=lambda snap: snap["elapsed_ms"],
    )
    return {"jobs": snapshots}


@router.get("/jobs/{job_id}")
def get_job_status(job_id: str) -> dict:
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan job not found")
    snapshot = job.snapshot()
    if snapshot["status"] in ("done", "failed", "cancelled") and job.result is not None:
        snapshot["result"] = job.result
    return snapshot


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str) -> dict:
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan job not found")
    if not job.request_cancel():
        raise HTTPException(status_code=409, detail="job is no longer running")
    return job.snapshot()