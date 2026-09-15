"""Automated retesting loop for remediated findings.

When a finding is marked as remediated, this service re-runs the
registered validator to verify the fix. Results are persisted back
to the database with timestamps for audit trails.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.db.models import EvidenceORM, FindingORM, ValidationORM
from app.db.repository import PersistenceRepository
from app.db.serialization import finding_orm_to_model
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.scanning.http_discovery import ScopedReconHttpClient
from app.scanning.scope import ReconScopeError, normalize_origin
from app.validation.dispatcher import dispatch

logger = logging.getLogger(__name__)


class RetestError(RuntimeError):
    """Raised when retesting fails due to invalid state or infrastructure."""


@dataclass(frozen=True)
class RetestResult:
    finding_id: str
    previous_status: str
    current_status: str
    retest_confirmed: bool
    validation_result: Dict[str, Any]
    retested_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "previous_status": self.previous_status,
            "current_status": self.current_status,
            "retest_confirmed": self.retest_confirmed,
            "validation_result": self.validation_result,
            "retested_at": self.retested_at,
        }


def _finding_to_domain(finding_orm: FindingORM) -> Optional[Finding]:
    """Convert a FindingORM row back to a domain Finding model."""
    try:
        return finding_orm_to_model(finding_orm)
    except Exception as exc:
        logger.warning(
            "Could not convert finding %s to domain model: %s",
            finding_orm.id, exc,
        )
        return None


def retest_finding(
    session: Session,
    *,
    scan_id: str,
    finding_id: str,
) -> RetestResult:
    """Re-run the validator for a finding to verify remediation.

    This re-tests the finding regardless of current status. If the
    finding was previously confirmed but is now rejected, it means
    the remediation was successful.
    """
    repository = PersistenceRepository(session)

    finding_orm = None
    for candidate in repository.list_findings_for_scan(scan_id):
        if candidate.id == finding_id:
            finding_orm = candidate
            break

    if finding_orm is None:
        raise RetestError(f"finding {finding_id!r} not found on scan {scan_id!r}")

    if not finding_orm.validator_id:
        raise RetestError(
            f"finding {finding_id!r} has no registered validator for retesting"
        )

    previous_status = finding_orm.status

    finding = _finding_to_domain(finding_orm)
    if finding is None:
        raise RetestError(
            f"finding {finding_id!r} could not be converted for retesting"
        )

    # Execute validation
    try:
        target = normalize_origin(finding_orm.target)
    except ReconScopeError as exc:
        raise RetestError(
            f"target origin validation failed for {finding_orm.target}: {exc}"
        ) from exc

    try:
        with ScopedReconHttpClient(target) as http_client:
            result = dispatch(finding, http_client)
    except Exception as exc:
        raise RetestError(
            f"validation dispatch failed for finding {finding_id!r}: {exc}"
        ) from exc

    # Determine new status based on validation result
    current_status = result.status
    retest_confirmed = (
        previous_status == ValidationStatus.CONFIRMED
        and current_status == ValidationStatus.REJECTED
    )

    # Persist the new validation record
    validation_record = repository.persist_validation(
        finding_id=finding_id,
        result=result,
    )
    repository.persist_evidence(
        validation_id=validation_record.id,
        finding_id=finding_id,
        evidence_type="retest_result",
        evidence_json={
            "retest": True,
            "previous_status": previous_status,
            "current_status": current_status,
            "retest_confirmed": retest_confirmed,
            "result": result.evidence,
        },
    )

    # Update the finding status
    finding_orm.status = current_status
    session.flush()

    retested_at = datetime.now(timezone.utc).isoformat()

    return RetestResult(
        finding_id=finding_id,
        previous_status=previous_status,
        current_status=current_status,
        retest_confirmed=retest_confirmed,
        validation_result=result.to_dict(),
        retested_at=retested_at,
    )


def retest_findings_batch(
    session: Session,
    *,
    scan_id: str,
    finding_ids: Optional[List[str]] = None,
    only_confirmed: bool = False,
) -> List[RetestResult]:
    """Retest multiple findings in a batch.

    If finding_ids is provided, only those findings are retested.
    If only_confirmed is True, only findings with CONFIRMED status are retested.
    """
    repository = PersistenceRepository(session)
    all_findings = repository.list_findings_for_scan(scan_id)

    if finding_ids:
        target_findings = [
            f for f in all_findings if f.id in set(finding_ids)
        ]
    elif only_confirmed:
        target_findings = [
            f for f in all_findings
            if f.status == ValidationStatus.CONFIRMED and f.validator_id
        ]
    else:
        target_findings = [
            f for f in all_findings
            if f.validator_id
            and f.status in {ValidationStatus.CONFIRMED, ValidationStatus.MANUAL_REVIEW}
        ]

    results = []
    for finding_orm in target_findings:
        try:
            result = retest_finding(
                session,
                scan_id=scan_id,
                finding_id=finding_orm.id,
            )
            results.append(result)
        except RetestError as exc:
            logger.warning("retest failed for finding %s: %s", finding_orm.id, exc)
            results.append(RetestResult(
                finding_id=finding_orm.id,
                previous_status=finding_orm.status,
                current_status=finding_orm.status,
                retest_confirmed=False,
                validation_result={"error": str(exc)},
                retested_at=datetime.now(timezone.utc).isoformat(),
            ))

    session.commit()
    return results
