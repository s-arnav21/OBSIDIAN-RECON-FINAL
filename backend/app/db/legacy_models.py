"""Legacy shared Obsidian Recon database models.

This module is a byte-for-byte port of the previous project's
`app/db/models.py` (the "shared PostgreSQL database"). It powers the
exploitation workflow against the ORIGINAL database (legacy volume
`obsidian-recon_postgres_data`, database `obsidian_recon`):

  - recon:    targets, recon_results
  - findings: findings, evidence
  - exploit:  exploit.sessions, exploit.exploits, exploit.shells (schema `exploit`)

It intentionally mirrors the old schema exactly so the old and new directories
stay in sync and the exploitation team reads from the same database as before.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Target(Base):
    """A single recon target and its current scan/exploitation state."""

    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String, nullable=False, unique=True)
    name = Column(String)
    added_at = Column(DateTime, default=utcnow)
    last_scanned_at = Column(DateTime)
    overall_risk_score = Column(Float)
    total_findings = Column(Integer, default=0)
    scan_status = Column(String, default="pending")
    exploitation_status = Column(String, default="not_attempted")
    compromised = Column(Boolean, default=False)

    recon_results = relationship("ReconResult", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target")
    sessions = relationship("ExploitSession", back_populates="target")


class ReconResult(Base):
    """JSONB snapshot of a ReconResult dataclass for a target."""

    __tablename__ = "recon_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    target = relationship("Target", back_populates="recon_results")
    payload = Column(JSON, nullable=False)  # ReconResult.to_dict()
    created_at = Column(DateTime, default=utcnow)


class Scan(Base):
    """A scan run against a target (scanner execution)."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    name = Column(String)  # operator-assigned scan name/purpose
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime)
    triggered_by = Column(String)
    tool_used = Column(String)

    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    """A vulnerability finding on a target (canonical normalized form)."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    scan_id = Column(Integer, ForeignKey("scans.id"))
    template_id = Column(String)
    vulnerability_name = Column(String)
    category = Column(String)
    severity = Column(String, default="medium")
    status = Column(String, default="open")
    confidence_score = Column(Float)
    confidence_level = Column(String)
    cve = Column(String)
    port = Column(Integer)
    parameter_affected = Column(String)
    payload = Column(JSON)  # full Finding.to_dict() detail
    created_at = Column(DateTime, default=utcnow)

    target = relationship("Target", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    exploit = relationship("Exploit", back_populates="finding")


class Evidence(Base):
    """Evidence attached to a finding."""

    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    payload = Column(JSON)
    created_at = Column(DateTime, default=utcnow)


class ExploitSession(Base):
    """Exploitation-team session tied to a recon target."""

    __tablename__ = "sessions"
    __table_args__ = {"schema": "exploit"}

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    session_name = Column(String, nullable=False)
    tool_used = Column(String)
    status = Column(String, default="pending")
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime)

    target = relationship("Target", back_populates="sessions")
    exploits = relationship("Exploit", back_populates="session")
    shells = relationship("Shell", back_populates="session")


class Exploit(Base):
    """An exploit launched against a target/finding."""

    __tablename__ = "exploits"
    __table_args__ = {"schema": "exploit"}

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("exploit.sessions.id"))
    finding_id = Column(Integer, ForeignKey("findings.id"))
    module_name = Column(String)
    description = Column(Text)
    outcome = Column(String)
    output = Column(Text)
    created_at = Column(DateTime, default=utcnow)

    session = relationship("ExploitSession", back_populates="exploits")
    finding = relationship("Finding", back_populates="exploit")


class Shell(Base):
    """A shell/credential obtained through exploitation."""

    __tablename__ = "shells"
    __table_args__ = {"schema": "exploit"}

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("exploit.sessions.id"))
    shell_type = Column(String)
    host = Column(String)
    port = Column(Integer)
    username = Column(String)
    password = Column(String)
    active = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    session = relationship("ExploitSession", back_populates="shells")


__all__ = [
    "Base",
    "Target",
    "ReconResult",
    "Scan",
    "Finding",
    "Evidence",
    "ExploitSession",
    "Exploit",
    "Shell",
]