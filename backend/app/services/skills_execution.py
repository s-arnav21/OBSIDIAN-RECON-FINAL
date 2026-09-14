"""Bridge between the synced legacy skill system and the canonical pipeline.

Legacy skills produce ``RawFinding`` rows and mutate a ``SkillContext``.
The canonical architecture consumes ``Finding`` (validated). This service
executes the skill runner against a target, normalizes the raw findings into
the canonical model, then dispatches each through the validator layer so the
result feeds the standard attack-chain / persistence path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
from uuid import uuid4

from app.attack_chain.engine import build_attack_paths
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.attack_chain import AttackChain
from app.models.finding import Finding, ValidationStatus
from app.models.scanner import RawFinding
from app.models.validation import ValidationResult
from app.validation.dispatcher import apply_validation_result, dispatch


@dataclass
class SkillsExecutionResult:
    phase: str
    skill_results: list = field(default_factory=list)
    normalized: List[Finding] = field(default_factory=list)
    validated: List[Finding] = field(default_factory=list)
    chains: List[AttackChain] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "skill_runs": [
                {
                    "skill": r.skill_name,
                    "success": r.success,
                    "findings": len(r.findings),
                    "duration_ms": r.duration_ms,
                    "error": r.error,
                }
                for r in self.skill_results
            ],
            "findings": [f.to_dict() for f in self.validated],
            "chains": [chain.to_dict() for chain in self.chains],
        }


def _host_from_context(ctx) -> str:
    return getattr(ctx, "host", None) or getattr(ctx, "target_url", "")


def _build_scan_id(ctx) -> str:
    return getattr(ctx, "scan_id", None) or f"skills-{uuid4()}"


def run_skills_phase(
    ctx,
    *,
    phase: str = "recon",
    profile=None,
    cancel_event=None,
    on_step=None,
    run_validators: bool = True,
    dispatch_session: Any = None,
) -> SkillsExecutionResult:
    """Execute one skill phase and bridge the findings into canonical form.

    Args:
        ctx: SkillContext (must implement target_url/host/scan_id/authorized
            and the mutable context fields the runner expects).
        phase: skill category to run ("recon", "network", "web", "post",
            "report", or "all").
        profile: optional ScanProfile used by the deterministic selector.
        cancel_event: cooperative cancellation handle passed to skills.
        on_step: progress callback forwarded to the skill runner.
        run_validators: if True, dispatch each normalized finding through the
            deterministic validator layer (default True).
        dispatch_session: HTTP session handed to validators that require one.
    """
    from skills import load_all_skills
    from skills.runner import run_skills

    load_all_skills()

    scan_id = _build_scan_id(ctx)
    ctx.scan_id = scan_id

    results = run_skills(
        ctx,
        phase=phase,
        on_step=on_step,
        cancel_event=cancel_event,
        profile=profile,
    )

    outcome = SkillsExecutionResult(phase=phase, skill_results=results)

    raw_findings: List[RawFinding] = list(ctx.raw_findings or [])
    if not raw_findings:
        return outcome

    from pipeline.normalize import normalize_all

    host = _host_from_context(ctx)
    normalized = normalize_all(raw_findings, scan_id=scan_id, asset_id=host)
    outcome.normalized.extend(normalized)

    if run_validators:
        for finding in normalized:
            validation: ValidationResult = dispatch(finding, dispatch_session)
            validated = apply_validation_result(finding, validation)
            outcome.validated.append(enrich_finding_model(validated))
    else:
        outcome.validated.extend(normalized)

    if outcome.validated:
        outcome.chains = list(
            build_attack_paths([f for f in outcome.validated
                                if f.validation_status != ValidationStatus.REJECTED])
        )

    return outcome


__all__ = ["SkillsExecutionResult", "run_skills_phase"]