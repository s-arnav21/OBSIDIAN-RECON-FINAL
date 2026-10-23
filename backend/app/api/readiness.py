"""Non-secret component readiness for the local prototype UI."""

from __future__ import annotations

import os
import shutil
from typing import Dict, Generator, Optional

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import get_session_factory


router = APIRouter(prefix="/api", tags=["readiness"])


def get_optional_readiness_db() -> Generator[Optional[Session], None, None]:
    """Yield no session when configuration is absent instead of leaking details."""
    try:
        session = get_session_factory()()
    except Exception:
        yield None
        return
    try:
        yield session
    finally:
        session.close()


def _database_status(session: Optional[Session]) -> str:
    if session is None:
        return "unavailable"
    try:
        session.execute(text("SELECT 1"))
    except Exception:
        session.rollback()
        return "unavailable"
    return "ready"


def _scanner_status(environment_name: str, binary_name: str) -> str:
    configured = os.getenv(environment_name, "").strip()
    # Prefer the explicit env path, but fall back to PATH resolution so tools
    # baked into the image (nmap/nuclei in /usr/bin & /usr/local/bin) are
    # reported correctly even when the env override is left empty.
    path = configured or shutil.which(binary_name)
    if not path:
        return "not_configured"
    return "ready" if shutil.which(path) else "unavailable"


@router.get("/readiness")
def readiness(
    session: Optional[Session] = Depends(get_optional_readiness_db),
) -> Dict[str, object]:
    components = {
        "backend": {"status": "ready"},
        "postgresql": {"status": _database_status(session)},
        "nmap": {"status": _scanner_status("RECON_NMAP_PATH", "nmap")},
        "nuclei": {"status": _scanner_status("RECON_NUCLEI_PATH", "nuclei")},
    }
    overall = (
        "ready"
        if all(component["status"] == "ready" for component in components.values())
        else "degraded"
    )
    return {"status": overall, "components": components}
