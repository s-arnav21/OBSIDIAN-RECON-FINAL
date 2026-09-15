"""Small transaction-oriented repository for scan persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import (
    AssetORM,
    AttackChainORM,
    AttackChainStepORM,
    EvidenceORM,
    ExploitORM,
    ExploitSessionORM,
    FindingORM,
    MitreMappingORM,
    ScanORM,
    ServiceORM,
    ShellORM,
    TargetVerificationORM,
    ValidationORM,
)
from app.models.attack_chain import AttackChain
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult


class PersistenceNotFoundError(LookupError):
    """Raised when an update references a record that does not exist."""


class PersistenceConflictError(ValueError):
    """Raised when persistence would overwrite an existing immutable record."""


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4()}"


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid ISO-8601 timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class PersistenceRepository:
    """Persist and retrieve ORM records within a caller-owned transaction."""

    def __init__(self, session: Session) -> None:
        if not isinstance(session, Session):
            raise TypeError("session must be a SQLAlchemy Session")
        self.session = session

    def _require_scan(self, scan_id: str) -> ScanORM:
        scan = self.session.get(ScanORM, scan_id)
        if scan is None:
            raise PersistenceNotFoundError(f"scan {scan_id!r} was not found")
        return scan

    def _require_asset(self, asset_id: str, scan_id: str) -> AssetORM:
        asset = self.session.get(AssetORM, asset_id)
        if asset is None:
            raise PersistenceNotFoundError(f"asset {asset_id!r} was not found")
        if asset.scan_id != scan_id:
            raise PersistenceConflictError(
                f"asset {asset_id!r} belongs to a different scan"
            )
        return asset

    def create_scan(
        self,
        *,
        target_url: str,
        authorized: bool,
        status: str = "created",
        scan_id: Optional[str] = None,
        started_at: Optional[datetime] = None,
    ) -> ScanORM:
        record = ScanORM(
            id=scan_id or _new_id("scan"),
            target_url=target_url,
            status=status,
            authorized=authorized,
            started_at=started_at or datetime.now(timezone.utc),
        )
        self.session.add(record)
        self.session.flush()
        return record

    def create_target_verification(
        self,
        *,
        origin: str,
        hostname: str,
        token_digest: str,
        challenge_token: str,
        expires_at: datetime,
        verification_id: Optional[str] = None,
    ) -> TargetVerificationORM:
        record = TargetVerificationORM(
            id=verification_id or _new_id("target-verification"),
            origin=origin,
            hostname=hostname,
            token_digest=token_digest,
            challenge_token=challenge_token,
            status="pending",
            expires_at=expires_at,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def get_target_verification(
        self,
        verification_id: str,
    ) -> Optional[TargetVerificationORM]:
        return self.session.get(TargetVerificationORM, verification_id)

    def latest_target_verification(
        self,
        origin: str,
    ) -> Optional[TargetVerificationORM]:
        statement = (
            select(TargetVerificationORM)
            .where(TargetVerificationORM.origin == origin)
            .order_by(
                TargetVerificationORM.created_at.desc(),
                TargetVerificationORM.id.desc(),
            )
            .limit(1)
        )
        return self.session.scalar(statement)

    def verified_target_verification(
        self,
        origin: str,
    ) -> Optional[TargetVerificationORM]:
        statement = (
            select(TargetVerificationORM)
            .where(
                TargetVerificationORM.origin == origin,
                TargetVerificationORM.status == "verified",
            )
            .order_by(
                TargetVerificationORM.verified_at.desc(),
                TargetVerificationORM.created_at.desc(),
            )
            .limit(1)
        )
        return self.session.scalar(statement)

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        *,
        completed_at: Optional[datetime] = None,
        failure_reason: Optional[str] = None,
    ) -> ScanORM:
        record = self.session.get(ScanORM, scan_id)
        if record is None:
            raise PersistenceNotFoundError(f"scan {scan_id!r} was not found")
        record.status = status
        record.failure_reason = failure_reason
        if completed_at is not None:
            record.completed_at = completed_at
        elif status in {"completed", "failed"}:
            record.completed_at = datetime.now(timezone.utc)
        self.session.flush()
        return record

    def persist_asset(
        self,
        *,
        scan_id: str,
        asset_id: Optional[str] = None,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> AssetORM:
        self._require_scan(scan_id)
        record = AssetORM(
            id=asset_id or _new_id("asset"),
            scan_id=scan_id,
            hostname=hostname,
            ip_address=ip_address,
            base_url=base_url,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def persist_service(
        self,
        *,
        scan_id: str,
        asset_id: str,
        service_id: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        service_name: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        state: Optional[str] = None,
        source: Optional[str] = None,
    ) -> ServiceORM:
        self._require_scan(scan_id)
        self._require_asset(asset_id, scan_id)
        record = ServiceORM(
            id=service_id or _new_id("service"),
            scan_id=scan_id,
            asset_id=asset_id,
            port=port,
            protocol=protocol,
            service_name=service_name,
            product=product,
            version=version,
            state=state,
            source=source,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def persist_finding(self, finding: Finding) -> FindingORM:
        if not isinstance(finding, Finding):
            raise TypeError("finding must be a Finding domain model")
        if self.session.get(FindingORM, finding.finding_id) is not None:
            raise PersistenceConflictError(
                f"finding {finding.finding_id!r} already exists"
            )
        self._require_scan(finding.scan_id)
        if finding.asset_id is not None:
            self._require_asset(finding.asset_id, finding.scan_id)
        record = FindingORM(
            id=finding.finding_id,
            scan_id=finding.scan_id,
            asset_id=finding.asset_id,
            source=finding.source,
            scanner_template_id=finding.template_id,
            validator_id=finding.validator_id,
            vulnerability_type=finding.vulnerability_type,
            severity=finding.severity,
            target=finding.target,
            endpoint=finding.endpoint,
            http_method=finding.http_method,
            parameter_name=finding.parameter_name,
            parameter_location=finding.parameter_location,
            status=finding.validation_status,
            created_at=_parse_datetime(finding.observed_at),
        )
        self.session.add(record)
        self.session.flush()
        return record

    def persist_validation(
        self,
        *,
        finding_id: str,
        result: ValidationResult,
        validation_id: Optional[str] = None,
    ) -> ValidationORM:
        if not isinstance(result, ValidationResult):
            raise TypeError("result must be a ValidationResult domain model")
        if self.session.get(FindingORM, finding_id) is None:
            raise PersistenceNotFoundError(f"finding {finding_id!r} was not found")
        reason = result.evidence.get("reason")
        record = ValidationORM(
            id=validation_id or _new_id("validation"),
            finding_id=finding_id,
            validator_id=result.validator,
            status=result.status,
            confidence=result.confidence,
            decision_reason=reason if isinstance(reason, str) else None,
            validated_at=_parse_datetime(result.timestamp),
        )
        self.session.add(record)
        self.session.flush()
        return record

    def persist_evidence(
        self,
        *,
        validation_id: str,
        finding_id: str,
        evidence_json: object,
        evidence_type: Optional[str] = None,
        evidence_id: Optional[str] = None,
    ) -> EvidenceORM:
        validation = self.session.get(ValidationORM, validation_id)
        if validation is None:
            raise PersistenceNotFoundError(
                f"validation {validation_id!r} was not found"
            )
        if validation.finding_id != finding_id:
            raise PersistenceConflictError(
                "evidence finding does not match its validation"
            )
        record = EvidenceORM(
            id=evidence_id or _new_id("evidence"),
            validation_id=validation_id,
            finding_id=finding_id,
            evidence_type=evidence_type,
            evidence_json=evidence_json,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def update_finding_validation_status(
        self,
        finding_id: str,
        status: str,
    ) -> FindingORM:
        """Persist a new validation status onto an existing finding record."""
        record = self.session.get(FindingORM, finding_id)
        if record is None:
            raise PersistenceNotFoundError(
                f"finding {finding_id!r} was not found"
            )
        if isinstance(status, str) and not status.strip():
            raise ValueError("status must be a non-empty string")
        record.status = ValidationStatus.normalize(status)
        self.session.flush()
        return record

    def persist_mitre_mapping(
        self,
        finding: Finding,
        *,
        mapping_id: Optional[str] = None,
        mapping_confidence: Optional[float] = None,
    ) -> MitreMappingORM:
        if not all((
            finding.mitre_technique_id,
            finding.mitre_technique_name,
            finding.mitre_tactic,
        )):
            raise ValueError("finding does not contain a complete MITRE mapping")
        if self.session.get(FindingORM, finding.finding_id) is None:
            raise PersistenceNotFoundError(
                f"finding {finding.finding_id!r} was not found"
            )
        record = MitreMappingORM(
            id=mapping_id or _new_id("mapping"),
            finding_id=finding.finding_id,
            technique_id=finding.mitre_technique_id,
            technique_name=finding.mitre_technique_name,
            tactic=finding.mitre_tactic,
            mapping_confidence=(
                finding.validation_confidence
                if mapping_confidence is None
                else mapping_confidence
            ),
        )
        self.session.add(record)
        self.session.flush()
        return record

    def persist_attack_chain(self, chain: AttackChain) -> AttackChainORM:
        if not isinstance(chain, AttackChain):
            raise TypeError("chain must be an AttackChain domain model")
        if self.session.get(AttackChainORM, chain.chain_id) is not None:
            raise PersistenceConflictError(
                f"attack chain {chain.chain_id!r} already exists"
            )
        self._require_scan(chain.scan_id)
        self._require_asset(chain.asset_id, chain.scan_id)

        record = AttackChainORM(
            id=chain.chain_id,
            scan_id=chain.scan_id,
            asset_id=chain.asset_id,
            status=chain.status,
            confidence=chain.confidence,
            created_at=_parse_datetime(chain.generated_at),
        )
        self.session.add(record)
        self.session.flush()

        for step in sorted(chain.steps, key=lambda item: item.step_number):
            persisted_finding = self.session.get(FindingORM, step.finding_id)
            if persisted_finding is None:
                raise PersistenceNotFoundError(
                    f"chain step finding {step.finding_id!r} was not persisted"
                )
            if persisted_finding.scan_id != chain.scan_id:
                raise PersistenceConflictError(
                    "chain step finding belongs to a different scan"
                )
            if persisted_finding.asset_id != chain.asset_id:
                raise PersistenceConflictError(
                    "chain step finding belongs to a different asset"
                )
            capability = step.provides[0] if step.provides else None
            self.session.add(AttackChainStepORM(
                id=_new_id("chain-step"),
                chain_id=chain.chain_id,
                step_number=step.step_number,
                finding_id=step.finding_id,
                technique_id=step.mitre_technique_id,
                capability=capability,
            ))
        self.session.flush()
        return record

    def get_scan(self, scan_id: str) -> Optional[ScanORM]:
        statement = (
            select(ScanORM)
            .where(ScanORM.id == scan_id)
            .options(
                selectinload(ScanORM.assets),
                selectinload(ScanORM.services),
            )
        )
        return self.session.scalar(statement)

    def list_scans(self, limit: Optional[int] = None) -> List[ScanORM]:
        statement = (
            select(ScanORM)
            .order_by(ScanORM.created_at.desc(), ScanORM.id.desc())
        )
        if limit is not None:
            statement = statement.limit(limit)
        return list(self.session.scalars(statement))

    def list_findings_for_scan(self, scan_id: str) -> List[FindingORM]:
        statement = (
            select(FindingORM)
            .where(FindingORM.scan_id == scan_id)
            .options(
                selectinload(FindingORM.validations).selectinload(
                    ValidationORM.evidence_records
                ),
                selectinload(FindingORM.mitre_mappings),
            )
            .order_by(FindingORM.created_at, FindingORM.id)
        )
        return list(self.session.scalars(statement))

    def list_attack_chains_for_scan(self, scan_id: str) -> List[AttackChainORM]:
        statement = (
            select(AttackChainORM)
            .where(AttackChainORM.scan_id == scan_id)
            .options(selectinload(AttackChainORM.steps))
            .order_by(AttackChainORM.created_at, AttackChainORM.id)
        )
        return list(self.session.scalars(statement))

    # ------------------------------------------------------------------
    # Exploitation (sessions, exploits, shells)
    # ------------------------------------------------------------------

    def create_exploit_session(
        self,
        *,
        session_id: str,
        scan_id: str,
        target_url: str,
        session_name: str,
        tool_used: Optional[str] = None,
        status: str = "pending",
    ) -> ExploitSessionORM:
        self._require_scan(scan_id)
        record = ExploitSessionORM(
            id=session_id,
            scan_id=scan_id,
            target_url=target_url,
            session_name=session_name,
            tool_used=tool_used,
            status=status,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def persist_exploit(
        self,
        *,
        exploit_id: str,
        session_id: str,
        module_name: str,
        finding_id: Optional[str] = None,
        technique_id: Optional[str] = None,
        description: Optional[str] = None,
        outcome: Optional[str] = None,
        output: Optional[str] = None,
    ) -> ExploitORM:
        self._require_exploit_session(session_id)
        record = ExploitORM(
            id=exploit_id,
            session_id=session_id,
            finding_id=finding_id,
            technique_id=technique_id,
            module_name=module_name,
            description=description,
            outcome=outcome,
            output=output,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def persist_shell(
        self,
        *,
        shell_id: str,
        session_id: str,
        shell_type: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        active: bool = False,
    ) -> ShellORM:
        self._require_exploit_session(session_id)
        record = ShellORM(
            id=shell_id,
            session_id=session_id,
            shell_type=shell_type,
            host=host,
            port=port,
            username=username,
            password=password,
            active=active,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def update_exploit_session_status(
        self,
        session_id: str,
        status: str,
        *,
        finished_at: Optional[datetime] = None,
    ) -> ExploitSessionORM:
        record = self._require_exploit_session(session_id)
        record.status = status
        if finished_at is not None:
            record.finished_at = finished_at
        self.session.flush()
        return record

    def get_exploit_session(self, session_id: str) -> Optional[ExploitSessionORM]:
        statement = (
            select(ExploitSessionORM)
            .where(ExploitSessionORM.id == session_id)
            .options(
                selectinload(ExploitSessionORM.exploits),
                selectinload(ExploitSessionORM.shells),
            )
        )
        return self.session.scalar(statement)

    def list_exploit_sessions(self, scan_id: Optional[str] = None) -> List[ExploitSessionORM]:
        statement = select(ExploitSessionORM)
        if scan_id:
            statement = statement.where(ExploitSessionORM.scan_id == scan_id)
        statement = statement.options(
            selectinload(ExploitSessionORM.exploits),
            selectinload(ExploitSessionORM.shells),
        ).order_by(ExploitSessionORM.created_at, ExploitSessionORM.id)
        return list(self.session.scalars(statement))

    def list_exploits_for_session(self, session_id: str) -> List[ExploitORM]:
        statement = (
            select(ExploitORM)
            .where(ExploitORM.session_id == session_id)
            .order_by(ExploitORM.created_at, ExploitORM.id)
        )
        return list(self.session.scalars(statement))

    def list_shells_for_session(self, session_id: str) -> List[ShellORM]:
        statement = (
            select(ShellORM)
            .where(ShellORM.session_id == session_id)
            .order_by(ShellORM.created_at, ShellORM.id)
        )
        return list(self.session.scalars(statement))

    def _require_exploit_session(self, session_id: str) -> ExploitSessionORM:
        record = self.session.scalar(
            select(ExploitSessionORM).where(ExploitSessionORM.id == session_id)
        )
        if record is None:
            raise PersistenceNotFoundError(
                f"exploit session {session_id!r} not found"
            )
        return record
