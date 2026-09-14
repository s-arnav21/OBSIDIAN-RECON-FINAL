"""JSON-safe serialization for persistence API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult

from app.db.models import (
    AttackChainORM,
    ExploitORM,
    ExploitSessionORM,
    FindingORM,
    ScanORM,
    ShellORM,
)


def _timestamp(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def scan_to_dict(scan: ScanORM) -> Dict[str, Any]:
    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "authorized": scan.authorized,
        "started_at": _timestamp(scan.started_at),
        "completed_at": _timestamp(scan.completed_at),
        "failure_reason": scan.failure_reason,
        "created_at": _timestamp(scan.created_at),
    }


def finding_to_dict(finding: FindingORM) -> Dict[str, Any]:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "asset_id": finding.asset_id,
        "source": finding.source,
        "scanner_template_id": finding.scanner_template_id,
        "validator_id": finding.validator_id,
        "vulnerability_type": finding.vulnerability_type,
        "severity": finding.severity,
        "target": finding.target,
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter_name": finding.parameter_name,
        "parameter_location": finding.parameter_location,
        "status": finding.status,
        "created_at": _timestamp(finding.created_at),
        "validations": [
            {
                "id": validation.id,
                "validator_id": validation.validator_id,
                "status": validation.status,
                "confidence": validation.confidence,
                "decision_reason": validation.decision_reason,
                "validated_at": _timestamp(validation.validated_at),
                "evidence": [
                    {
                        "id": evidence.id,
                        "evidence_type": evidence.evidence_type,
                        "evidence_json": evidence.evidence_json,
                        "created_at": _timestamp(evidence.created_at),
                    }
                    for evidence in validation.evidence_records
                ],
            }
            for validation in finding.validations
        ],
        "mitre_mappings": [
            {
                "id": mapping.id,
                "technique_id": mapping.technique_id,
                "technique_name": mapping.technique_name,
                "tactic": mapping.tactic,
                "mapping_confidence": mapping.mapping_confidence,
            }
            for mapping in finding.mitre_mappings
        ],
    }


def attack_chain_to_dict(chain: AttackChainORM) -> Dict[str, Any]:
    return {
        "id": chain.id,
        "scan_id": chain.scan_id,
        "asset_id": chain.asset_id,
        "status": chain.status,
        "confidence": chain.confidence,
        "created_at": _timestamp(chain.created_at),
        "steps": [
            {
                "id": step.id,
                "step_number": step.step_number,
                "finding_id": step.finding_id,
                "technique_id": step.technique_id,
                "capability": step.capability,
            }
            for step in sorted(chain.steps, key=lambda item: item.step_number)
        ],
    }


def exploit_to_dict(exploit: ExploitORM) -> Dict[str, Any]:
    return {
        "id": exploit.id,
        "session_id": exploit.session_id,
        "finding_id": exploit.finding_id,
        "technique_id": exploit.technique_id,
        "module_name": exploit.module_name,
        "description": exploit.description,
        "outcome": exploit.outcome,
        "output": exploit.output,
        "created_at": _timestamp(exploit.created_at),
    }


def shell_to_dict(shell: ShellORM) -> Dict[str, Any]:
    return {
        "id": shell.id,
        "session_id": shell.session_id,
        "shell_type": shell.shell_type,
        "host": shell.host,
        "port": shell.port,
        "username": shell.username,
        "active": shell.active,
        "created_at": _timestamp(shell.created_at),
    }


def exploit_session_to_dict(session: ExploitSessionORM) -> Dict[str, Any]:
    return {
        "id": session.id,
        "scan_id": session.scan_id,
        "target_url": session.target_url,
        "session_name": session.session_name,
        "tool_used": session.tool_used,
        "status": session.status,
        "started_at": _timestamp(session.started_at),
        "finished_at": _timestamp(session.finished_at),
        "created_at": _timestamp(session.created_at),
        "exploits": [
            {
                key: value
                for key, value in exploit_to_dict(exploit).items()
                if key != "session_id"
            }
            for exploit in sorted(session.exploits, key=lambda item: item.created_at)
        ],
        "shells": [
            {
                key: value
                for key, value in shell_to_dict(shell).items()
                if key != "session_id"
            }
            for shell in sorted(session.shells, key=lambda item: item.created_at)
        ],
    }


def finding_orm_to_model(f: FindingORM) -> Finding:
    """Convert a FindingORM row to a canonical Finding model for the agent."""
    # Map ORM status to validation status
    status_map = {
        "confirmed": ValidationStatus.CONFIRMED,
        "manual_review": ValidationStatus.MANUAL_REVIEW,
        "rejected": ValidationStatus.REJECTED,
        "detected": ValidationStatus.DETECTED,
        "likely": ValidationStatus.LIKELY,
        "error": ValidationStatus.ERROR,
    }
    validation_status = status_map.get(
        (f.status or "").lower(), ValidationStatus.MANUAL_REVIEW
    )

    # Pull confidence from most recent validation if available
    confidence = 0.6
    if f.validations:
        latest = sorted(f.validations, key=lambda v: v.validated_at or 0, reverse=True)
        if latest[0].confidence is not None:
            confidence = float(latest[0].confidence)

    # Pull MITRE data from mappings
    mitre_technique_id = None
    mitre_technique_name = None
    mitre_tactic = None
    if f.mitre_mappings:
        m = f.mitre_mappings[0]
        mitre_technique_id = m.technique_id
        mitre_technique_name = m.technique_name
        mitre_tactic = m.tactic

    asset_id = f.asset_id or f.scan_id

    return Finding(
        finding_id=f.id,
        scan_id=f.scan_id,
        asset_id=asset_id,
        target=f.target,
        host=f.target,
        source=f.source,
        vulnerability_type=f.vulnerability_type,
        severity=f.severity or "medium",
        endpoint=f.endpoint,
        template_id=f.scanner_template_id,
        validator_id=f.validator_id,
        http_method=f.http_method,
        parameter_name=f.parameter_name,
        parameter_location=f.parameter_location,
        validation_status=validation_status,
        validation_confidence=confidence,
        mitre_technique_id=mitre_technique_id,
        mitre_technique_name=mitre_technique_name,
        mitre_tactic=mitre_tactic,
    )
