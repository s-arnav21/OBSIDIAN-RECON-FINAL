"""Engine, session factory, and FastAPI dependency for the legacy shared DB.

The legacy database (`LEGACY_DATABASE_URL`, falling back to `DATABASE_URL`)
holds the ORIGINAL recon findings (targets, findings, recon_results) plus the
exploitation-team tables (`exploit.sessions`, `exploit.exploits`,
`exploit.shells`). It is intentionally separate from the unified recon schema
so both directories stay in sync and the exploit flow reads the same store as
before.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

LEGACY_DATABASE_URL_ENV = "LEGACY_DATABASE_URL"


class LegacyDatabaseConfigurationError(RuntimeError):
    """Raised when legacy persistence is requested without configuration."""


def get_legacy_database_url() -> str:
    """Return the configured legacy database URL without embedding credentials."""
    url = os.getenv(
        LEGACY_DATABASE_URL_ENV, os.getenv("DATABASE_URL", "")
    ).strip()
    if not url:
        raise LegacyDatabaseConfigurationError(
            f"{LEGACY_DATABASE_URL_ENV} must be configured before using "
            "the legacy exploit database"
        )
    return url


@lru_cache
def get_legacy_engine() -> Engine:
    """Return the process-wide legacy engine lazily."""
    return create_engine(get_legacy_database_url(), pool_pre_ping=True)


@lru_cache
def get_legacy_session_factory() -> sessionmaker[Session]:
    """Return the process-wide legacy session factory lazily."""
    return sessionmaker(
        bind=get_legacy_engine(),
        autoflush=False,
        expire_on_commit=False,
    )


def get_legacy_db() -> Generator[Session, None, None]:
    """Yield one SQLAlchemy session for a FastAPI request (legacy store)."""
    session = get_legacy_session_factory()()
    try:
        yield session
    finally:
        session.close()