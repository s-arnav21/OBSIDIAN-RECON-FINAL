"""Persistence bridge for the legacy pipeline.

The new architecture persists through ``app.db.repository.PersistenceRepository``
from the ``app.api.*`` / ``app.services.*`` layers. The legacy
``pipeline.recon.run_recon`` accepts an optional SQLAlchemy ``db`` session for
older call-sites; here we keep that contract but route it to the repository
so no stale ORM tables are referenced. If no usable session is supplied the
call degrades gracefully (the pipeline treats DB persistence as best-effort).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session

from app.db.repository import PersistenceRepository
from app.models.recon import ReconResult as ReconResultDTO

logger = logging.getLogger(__name__)


def _session_usable(db: Optional[Session]) -> bool:
    if db is None:
        return False
    try:
        sa_inspect(db)
        return True
    except Exception:
        return False


def persist_recon(db: Optional[Session], result: ReconResultDTO) -> dict:
    """Persist a ReconResult via the new repository if a session is available.

    Returns a dict with ids on success; raises on failure so the caller's
    try/except can degrade gracefully. Never persists when ``db`` is unusable.
    """
    if not _session_usable(db):
        raise RuntimeError("no usable DB session for recon persistence")

    repo = PersistenceRepository(db)  # type: ignore[arg-type]
    payload = result.to_dict()

    scan = repo.create_scan(
        scan_id=f"recon-{result.target}",
        target_url=result.target,
        authorized=False,
        status="recon",
    )

    primary = result.primary_asset
    if primary is not None:
        repo.persist_asset(
            scan_id=scan.id,
            hostname=primary.host,
            ip_address=primary.ip,
            base_url=primary.url,
        )

    return {"scan_id": scan.id, "target": result.target}


def persist_findings(db, target_url: str, report_findings, scan_name=None) -> dict:
    """No-op bridge kept for legacy call-sites; nothing references it in the
    new pipeline, and finding persistence lives in the services layer."""
    logger.debug("persist_findings called for %s (no-op in new architecture)", target_url)
    return {"scan_id": "", "target": target_url}