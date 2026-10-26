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


# ---------------------------------------------------------------------------
# Task-centric agent persistence (additive; the finding-centric tables above
# remain unchanged for backward compatibility).
# ---------------------------------------------------------------------------


class AgentTaskORM(Base):
    __tablename__ = "agent_tasks"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_goal: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String(4096), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    allowed_hosts: Mapped[Any] = mapped_column(json_document_type(), nullable=False)
    allowed_ports: Mapped[Any] = mapped_column(json_document_type(), nullable=False)
    authorized_lab_scope: Mapped[bool] = mapped_column(Boolean, nullable=False)
    input_files: Mapped[Any] = mapped_column(json_document_type(), nullable=False)
    expected_outputs: Mapped[Any] = mapped_column(json_document_type(), nullable=False)
    permitted_actions: Mapped[Any] = mapped_column(json_document_type(), nullable=False)
    maximum_steps: Mapped[int] = mapped_column(Integer, nullable=False)
    maximum_runtime: Mapped[int] = mapped_column(Integer, nullable=False)
    maximum_repair_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    network_policy: Mapped[str] = mapped_column(String(32), nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    current_status: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    current_step: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stop_reason: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    model_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    scope_json: Mapped[Any] = mapped_column(
        json_document_type(), nullable=False, default=dict
    )
    report_json_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    report_md_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    steps: Mapped[List["AgentTaskStepORM"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    code_versions: Mapped[List["AgentCodeVersionORM"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    artifacts: Mapped[List["AgentArtifactORM"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    evidence: Mapped[List["AgentEvidenceORM"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    reports: Mapped[List["AgentReportORM"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    approvals: Mapped[List["AgentApprovalORM"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    target_sessions: Mapped[List["AgentTargetSessionORM"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )


class AgentTaskStepORM(Base):
    __tablename__ = "agent_task_steps"
    __table_args__ = (
        UniqueConstraint(
            "task_id", "step_number", name="uq_agent_task_steps_task_order"
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    action_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    arguments: Mapped[Any] = mapped_column(
        json_document_type(), nullable=False, default=dict
    )
    target: Mapped[Optional[str]] = mapped_column(String(4096), nullable=True)
    expected_result: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    policy_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    policy_reason: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    observation: Mapped[Any] = mapped_column(
        json_document_type(), nullable=False, default=dict
    )
    verification: Mapped[Any] = mapped_column(
        json_document_type(), nullable=False, default=dict
    )
    retrieved_skills: Mapped[Any] = mapped_column(
        json_document_type(), nullable=False, default=list
    )
    model_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    response_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    task: Mapped[AgentTaskORM] = relationship(back_populates="steps")


class AgentCodeVersionORM(Base):
    __tablename__ = "agent_code_versions"
    __table_args__ = (
        UniqueConstraint(
            "task_id", "version", name="uq_agent_code_versions_task_version"
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("agent_task_steps.id", ondelete="SET NULL"), nullable=True, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    code: Mapped[str] = mapped_column(String, nullable=False)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    error: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    task: Mapped[AgentTaskORM] = relationship(back_populates="code_versions")


class AgentArtifactORM(Base):
    __tablename__ = "agent_artifacts"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("agent_task_steps.id", ondelete="SET NULL"), nullable=True, index=True
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[Any] = mapped_column(
        "metadata", json_document_type(), nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    task: Mapped[AgentTaskORM] = relationship(back_populates="artifacts")


class AgentEvidenceORM(Base):
    __tablename__ = "agent_evidence"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("agent_task_steps.id", ondelete="SET NULL"), nullable=True, index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(String(2048), nullable=False)
    payload: Mapped[Any] = mapped_column(
        json_document_type(), nullable=False, default=dict
    )
    artifact_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    task: Mapped[AgentTaskORM] = relationship(back_populates="evidence")


class AgentReportORM(Base):
    __tablename__ = "agent_reports"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    report_json: Mapped[Any] = mapped_column(
        json_document_type(), nullable=False, default=dict
    )
    report_md: Mapped[str] = mapped_column(String, nullable=False)
    json_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    md_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    task: Mapped[AgentTaskORM] = relationship(back_populates="reports")


class AgentApprovalORM(Base):
    __tablename__ = "agent_approvals"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("agent_task_steps.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decided_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    task: Mapped[AgentTaskORM] = relationship(back_populates="approvals")


class AgentTargetSessionORM(Base):
    __tablename__ = "agent_target_sessions"
    __table_args__ = (
        UniqueConstraint(
            "task_id", "session_key", name="uq_agent_target_sessions_task_key"
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    session_key: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="open")
    metadata_json: Mapped[Any] = mapped_column(
        "metadata", json_document_type(), nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    task: Mapped[AgentTaskORM] = relationship(back_populates="target_sessions")


class AgentAuditEventORM(Base):
    __tablename__ = "agent_audit_events"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("agent_tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    detail: Mapped[Any] = mapped_column(
        json_document_type(), nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
