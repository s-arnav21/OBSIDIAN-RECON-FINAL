"""SQLAlchemy persistence schema kept separate from domain models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def json_document_type() -> Any:
    """Use PostgreSQL JSONB while retaining SQLite test compatibility."""
    return JSON().with_variant(JSONB(), "postgresql")


class ScanORM(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failure_reason: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    assets: Mapped[List["AssetORM"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    services: Mapped[List["ServiceORM"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[List["FindingORM"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    attack_chains: Mapped[List["AttackChainORM"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class TargetVerificationORM(Base):
    """Persisted proof-of-control challenge for one exact canonical origin."""

    __tablename__ = "target_verifications"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    origin: Mapped[str] = mapped_column(
        String(512), nullable=False, unique=True
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    # Retained only while a challenge is actionable so the pending DNS
    # instruction can be retrieved. It is cleared on verification/expiry.
    challenge_token: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    status: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failure_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class AssetORM(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    base_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    scan: Mapped[ScanORM] = relationship(back_populates="assets")
    services: Mapped[List["ServiceORM"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[List["FindingORM"]] = relationship(back_populates="asset")
    attack_chains: Mapped[List["AttackChainORM"]] = relationship(
        back_populates="asset"
    )


class ServiceORM(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    service_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    scan: Mapped[ScanORM] = relationship(back_populates="services")
    asset: Mapped[AssetORM] = relationship(back_populates="services")


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    scanner_template_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    validator_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vulnerability_type: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    endpoint: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    parameter_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    parameter_location: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    scan: Mapped[ScanORM] = relationship(back_populates="findings")
    asset: Mapped[Optional[AssetORM]] = relationship(back_populates="findings")
    validations: Mapped[List["ValidationORM"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    evidence_records: Mapped[List["EvidenceORM"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    mitre_mappings: Mapped[List["MitreMappingORM"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    chain_steps: Mapped[List["AttackChainStepORM"]] = relationship(
        back_populates="finding"
    )


class ValidationORM(Base):
    __tablename__ = "validations"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    validator_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    decision_reason: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True
    )
    validated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    finding: Mapped[FindingORM] = relationship(back_populates="validations")
    evidence_records: Mapped[List["EvidenceORM"]] = relationship(
        back_populates="validation", cascade="all, delete-orphan"
    )


class EvidenceORM(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    validation_id: Mapped[str] = mapped_column(
        ForeignKey("validations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    evidence_json: Mapped[Any] = mapped_column(json_document_type(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    validation: Mapped[ValidationORM] = relationship(
        back_populates="evidence_records"
    )
    finding: Mapped[FindingORM] = relationship(back_populates="evidence_records")


class MitreMappingORM(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(String(64), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(255), nullable=False)
    mapping_confidence: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )

    finding: Mapped[FindingORM] = relationship(back_populates="mitre_mappings")


class AttackChainORM(Base):
    __tablename__ = "attack_chains"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    scan: Mapped[ScanORM] = relationship(back_populates="attack_chains")
    asset: Mapped[Optional[AssetORM]] = relationship(back_populates="attack_chains")
    steps: Mapped[List["AttackChainStepORM"]] = relationship(
        back_populates="chain",
        cascade="all, delete-orphan",
        order_by="AttackChainStepORM.step_number",
    )


class AttackChainStepORM(Base):
    __tablename__ = "attack_chain_steps"
    __table_args__ = (
        UniqueConstraint(
            "chain_id", "step_number", name="uq_attack_chain_steps_order"
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    chain_id: Mapped[str] = mapped_column(
        ForeignKey("attack_chains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    finding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    technique_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    capability: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    chain: Mapped[AttackChainORM] = relationship(back_populates="steps")
    finding: Mapped[Optional[FindingORM]] = relationship(back_populates="chain_steps")


class ExploitSessionORM(Base):
    """An exploitation session tied to a scan/target."""

    __tablename__ = "exploit_sessions"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    session_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_used: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    scan: Mapped[ScanORM] = relationship()
    exploits: Mapped[List["ExploitORM"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    shells: Mapped[List["ShellORM"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class ExploitORM(Base):
    """A single exploit attempt launched against a finding/session."""

    __tablename__ = "exploits"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("exploit_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    technique_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    module_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    outcome: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    output: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    session: Mapped[ExploitSessionORM] = relationship(back_populates="exploits")
    finding: Mapped[Optional[FindingORM]] = relationship()


class ShellORM(Base):
    """A shell / credential obtained through exploitation."""

    __tablename__ = "shells"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("exploit_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    shell_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    session: Mapped[ExploitSessionORM] = relationship(back_populates="shells")
