"""Async-capable full-scan service.

Runs the reference how-to pipeline end-to-end — passive OSINT recon
(``pipeline.recon.run_recon``) then the active scanner pass
(``pipeline.scanner.run_scanners``) — behind a job handle so the recon
browser can submit a scan, poll its live step journal, and render the
canonical findings + attack chains when it lands.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Optional

from app.attack_chain.engine import build_attack_paths
from app.core.profiles import ScanProfile, get_profile
from app.db.models import FindingORM
from app.db.repository import PersistenceConflictError, PersistenceRepository
from app.models.finding import Finding
from pipeline.recon import run_recon
from pipeline.scanner import run_scanners

logger = logging.getLogger(__name__)


@dataclass
class FullScanResult:
    scan_id: str
    target_url: str
    name: Optional[str] = None
    profile: Optional[ScanProfile] = None
    skill_runs: list = field(default_factory=list)
    scanners: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    persisted: dict = field(default_factory=dict)
    report_raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "name": self.name,
            "profile": self.profile.name if self.profile else "webapp",
            "skill_runs": self.skill_runs,
            "scanners": self.scanners,
            "findings": self.findings,
            "chains": self.chains,
            "persisted": self.persisted,
        }


def _new_scan_id(target: str) -> str:
    return f"scan-{uuid.uuid4().hex[:12]}"


def _asset_id_for(target: str, scan_id: str) -> str:
    """Per-scan asset id for the job's persisted asset row.

    The pipeline's normalized findings carry a deterministic asset id (stable
    across runs of the same target), so the DB asset row here is scoped to the
    individual scan to avoid PK collisions on re-scan. Findings themselves stay
    idempotent: re-runs skip existing finding ids.
    """
    import hashlib
    digest = hashlib.sha256(f"{scan_id}:{target}".encode("utf-8")).hexdigest()
    return f"asset-{digest[:16]}"


def _finding_rows(normalized: list[Finding]) -> list[dict]:
    return [f.to_dict() for f in normalized]


def _chain_rows(chains) -> list[dict]:
    out = []
    for chain in chains:
        d = chain.to_dict() if hasattr(chain, "to_dict") else vars(chain)
        out.append(d)
    return out


def run_full_scan(
    *,
    target_url: str,
    authorized: bool = False,
    name: Optional[str] = None,
    profile_name: Optional[str] = None,
    include: Optional[list[str]] = None,
    skip: Optional[list[str]] = None,
    timeout: Optional[int] = None,
    ports: Optional[str] = None,
    progress=None,
    cancel_event=None,
    persist: bool = True,
    session=None,
    **extra,
) -> FullScanResult:
    """Run full passive recon + active scan against ``target_url``.

    Mirrors the reference console job: run_recon (DNS/OSINT/fingerprint) feeds
    the skill context, then run_scanners drives the deterministic skill phases
    plus the classic scanners, subdomain chain, origin hunt, triage, validation,
    and normalization.

    Progress/cancel semantics are the same as run_scanners: ``progress``
    receives {"kind": "step_start"|"step_finish"|"findings", ...} events and
    ``cancel_event`` (a threading.Event) stops the pipeline between steps.

    Persisting is best-effort: a DB error is logged and ``persisted`` records
    the outcome without ever raising out of the scan.
    """
    profile = get_profile(profile_name) if isinstance(profile_name, str) else None
    if profile is None:
        profile = get_profile("webapp")
    scan_id = _new_scan_id(target_url)
    asset_id = _asset_id_for(target_url, scan_id)

    def _emit(kind: str, step_id: str, **event) -> None:
        if progress is None:
            return
        try:
            progress({"kind": kind, "id": step_id, **event})
        except Exception:
            logger.debug("progress callback failed", exc_info=True)

    _emit("step_start", "recon", label="recon (passive OSINT + DNS)", phase="recon")

    recon = run_recon(target_url)

    host = recon.primary_asset.host if recon.primary_asset else target_url

    _emit("step_finish", "recon", status="done")
    _emit("findings", "recon", findings=_finding_rows(_osint_finding_rows(recon)))

    report = run_scanners(
        target_url,
        recon=recon,
        include=include,
        skip=skip,
        timeout=timeout,
        ports=ports,
        progress=progress,
        cancel_event=cancel_event,
        profile=profile,
    )

    report_raw = report.to_dict()
    skill_runs = _skill_runs(report)
    scanners = [s.to_dict() for s in report.statuses]

    chains = _build_chains(report.normalized) if report.normalized else []
    rows = _finding_rows(report.normalized)

    persisted: dict = {}
    if persist:
        persisted = _persist(
            session=session,
            scan_id=scan_id,
            asset_id=asset_id,
            host=host,
            target_url=target_url,
            authorized=authorized,
            findings=report.normalized,
        )

    return FullScanResult(
        scan_id=scan_id,
        target_url=target_url,
        name=name,
        profile=profile,
        skill_runs=skill_runs,
        scanners=scanners,
        findings=rows,
        chains=chains,
        persisted=persisted,
        report_raw=report_raw,
    )


def _osint_finding_rows(recon) -> list[dict]:
    rows = []
    for f in recon.osint_findings or []:
        if isinstance(f, dict):
            rows.append(f)
    return rows


def _skill_runs(report) -> list[dict]:
    out = []
    for s in report.statuses:
        if not s.name.startswith("skill:"):
            continue
        out.append({
            "skill": s.name[len("skill:"):],
            "success": s.status == "ran",
            "status": s.status,
            "findings": s.findings_count,
            "duration_ms": (s.detail or {}).get("duration_ms"),
            "error": s.error,
            "warning": s.warning,
        })
    return out


def _build_chains(normalized: list[Finding]) -> list[dict]:
    try:
        return _chain_rows(build_attack_paths(normalized))
    except Exception:
        logger.debug("attack chain build failed", exc_info=True)
        return []


def _persist(*, session, scan_id: str, asset_id: str, host: str,
             target_url: str, authorized: bool,
             findings: list[Finding]) -> dict:
    if session is None:
        return {"status": "skipped", "reason": "no db session"}
    try:
        repo = PersistenceRepository(session)
        repo.create_scan(
            scan_id=scan_id,
            target_url=target_url,
            authorized=authorized,
            status="completed",
        )
        try:
            repo.persist_asset(
                scan_id=scan_id,
                asset_id=asset_id,
                hostname=host,
                base_url=target_url,
            )
        except Exception:
            logger.debug("asset persist conflict", exc_info=True)

        stored = skipped = 0
        for finding in findings:
            if finding.asset_id:
                finding.asset_id = asset_id
            finding.scan_id = scan_id
            if session.get(FindingORM, finding.finding_id) is not None:
                skipped += 1
                continue
            try:
                repo.persist_finding(finding)
                stored += 1
            except PersistenceConflictError:
                skipped += 1
            except Exception:
                logger.debug("finding persist failed", exc_info=True)
                session.rollback()
                break
        session.commit()
        logger.info("persisted scan %s: %d findings stored, %d skipped",
                    scan_id, stored, skipped)
        return {"status": "ok", "scan_id": scan_id, "findings_stored": stored,
                "findings_skipped": skipped}
    except Exception:
        logger.exception("full-scan persistence failed")
        try:
            session.rollback()
        except Exception:
            pass
        return {"status": "error"}


__all__ = ["run_full_scan", "FullScanResult"]