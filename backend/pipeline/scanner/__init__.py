"""Scanner package — exposes the scanner registry and run_scanners() facade.

Importing this package registers all built-in scanners (Nmap, Nuclei, HTTP
probe) in the registry. `run_scanners()` runs every available scanner against
a target and returns a ScannersReport: the aggregated findings PLUS per-scanner
status metadata. A scanner that fails is reported, never silently swallowed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from app.models.finding import Finding
from app.models.recon import ReconResult
from app.models.scanner import RawFinding
from app.models.validation import ValidationResult
from pipeline.evidence import EvidenceStore
from pipeline._errors import ScanCancelled
from pipeline.normalize import normalize_all
from pipeline.scanner import base
from pipeline.scanner import http_probe  # noqa: F401  (registers)
from pipeline.scanner import nmap_scanner  # noqa: F401  (registers)
from pipeline.scanner import nuclei_scanner  # noqa: F401  (registers)
from pipeline.scanner import nmap_tls  # noqa: F401  (registers)
from pipeline.scanner import subdomains_httpx  # noqa: F401  (registers "subdomains")
from pipeline.scanner import content_httpx  # noqa: F401  (registers "content")
from pipeline.scanner import waf_detect  # noqa: F401  (registers "waf_detect")
from pipeline.triage import TriageSummary, triage
from pipeline.validator import validate_findings


@dataclass
class ScannerStatus:
    name: str
    status: str  # "ran" | "unavailable" | "failed"
    findings_count: int = 0
    error: Optional[str] = None
    warning: Optional[str] = None
    detail: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "findings_count": self.findings_count,
            "error": self.error,
            "warning": self.warning,
            "detail": self.detail,
        }


@dataclass
class ScannersReport:
    findings: List[RawFinding] = field(default_factory=list)
    statuses: List[ScannerStatus] = field(default_factory=list)
    triage: Optional[TriageSummary] = None
    evidences: dict = field(default_factory=dict)          # evidence_id -> Evidence.to_dict()
    normalized: List[Finding] = field(default_factory=list)  # canonical findings
    validation: dict = field(default_factory=dict)           # fp_key -> ValidationResult.to_dict()
    evidence_store: EvidenceStore = field(default_factory=EvidenceStore)

    def to_dict(self) -> dict:
        d = {
            "total_findings": len(self.findings),
            "scanner_count": len(self.statuses),
            "scanners": [s.to_dict() for s in self.statuses],
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.evidences:
            d["evidences"] = self.evidences
        if self.normalized:
            d["normalized"] = [f.to_dict() for f in self.normalized]
        if self.validation:
            d["validation"] = {k: v.to_dict() if hasattr(v, "to_dict") else v
                               for k, v in self.validation.items()}
        if self.triage is not None:
            d["triage"] = self.triage.to_dict()
        if self.evidence_store and len(self.evidence_store) > 0:
            d["evidence_store"] = self.evidence_store.to_dict()
        return d


def run_scanners(
    target: str,
    recon: ReconResult | None = None,
    include: list[str] | None = None,
    skip: list[str] | None = None,
    timeout: int | None = None,
    ports: str | None = None,
    progress: callable | None = None,
    cancel_event=None,
    profile=None,
) -> ScannersReport:
    """Run all (or a filtered subset of) available scanners against a target.

    Scanner behavior:
        - unavailable  -> reported as 'unavailable', no attempt.
        - ScanError    -> reported as 'failed' with the error message.
        - any other error -> reported as 'failed'.
        - success      -> reported as 'ran' with its finding count.

    A single failing scanner never raises out of run_scanners.

    Args:
        target: URL or host to scan.
        recon: optional prior recon result (used to derive host/port hints).
        include: if given, only run scanners with these names.
        skip: if given, do not run scanners with these names.
        timeout: optional per-scanner execution budget (seconds).
        ports: optional nmap port list override (e.g. "80,443").
        progress: optional real-time progress callback. Receives events:
            {"kind": "step_start", "id": ..., "label": ..., "phase": ...}
            {"kind": "step_finish", "id": ..., "status": "done"|"failed"|"skipped",
             "findings": n, "error": str|None}
        cancel_event: optional threading.Event; when set, the pipeline stops
            between steps and raises ScanCancelled so the job can be marked
            'cancelled' (not 'failed').
        profile: optional ScanProfile. Its skip_scanners are merged into
            `skip`, and skill selection/exploit gating is applied to the
            skill phases.

    Returns:
        ScannersReport (findings + per-scanner status metadata).
    """
    target_url = _derive_url(target, recon)

    # Exploit enablement: a profile that explicitly allows exploit skills
    # propagates to the process-global gate so the skill phase AND any skill
    # reading the env/settings agree with the request.
    if profile is not None and profile.allow_exploit_skills:
        from app.core.config import settings as _settings
        if not _settings.ALLOW_EXPLOIT_SKILLS:
            _settings.ALLOW_EXPLOIT_SKILLS = True
            os.environ["ALLOW_EXPLOIT_SKILLS"] = "true"

    scanner_instances = base.all_scanners()
    if include:
        scanner_instances = [s for s in scanner_instances if s.name in include]
    skip = set(skip or [])
    if profile is not None:
        skip.update(profile.skip_scanners)
    if skip:
        scanner_instances = [s for s in scanner_instances if s.name not in skip]

    # P3.4 — run the subdomain scanner FIRST so its discovered live subdomains
    # are available to the chained deep-scan stage that follows.
    scanner_instances = _order_subdomain_first(scanner_instances)

    kwargs_by_scanner = _build_scanner_kwargs(timeout, ports, cancel_event,
                                              profile=profile)
    report = ScannersReport()
    evidence_store = EvidenceStore()
    report.evidence_store = evidence_store  # share the same store for evidence emission

    # P2.3 — surface passive OSINT findings (expiring domain, IP-in-SAN,
    # historical sensitive path, shared hosting) alongside active findings so
    # they flow through triage, validation, and normalization uniformly.
    merged_osint = _osint_findings_from_recon(recon)
    report.findings.extend(merged_osint)
    _emit_findings(progress, merged_osint, "recon")

    # Skills system — run the deterministic skill phases (recon → network →
    # web → exploit → post). Skill findings are appended into report.findings
    # so they flow through triage/validation/normalization like everything else.
    _raise_if_cancelled(cancel_event)
    already_ran = _run_skill_phases(report, target_url, recon, progress,
                                    cancel_event, profile=profile)

    for scanner in scanner_instances:
        _raise_if_cancelled(cancel_event)
        _run_one(report, evidence_store, scanner, target_url,
                 kwargs_by_scanner.get(scanner.name, {}), progress)

    # Second skill pass (web → post) over the ACCUMULATED scanner findings.
    #
    # The first skill pass (above) runs before the scanners, so skills only
    # ever gate on what the recon/fingerprint skills derived for the *root*
    # page. But content discovery often reveals a WordPress (or other) app
    # living under a subdirectory (e.g. /secret/wp-admin, /secret/xmlrpc.php)
    # that the root fingerprint missed. Re-running the web + post skills after
    # the content scanners feed those discovered paths back into the skill
    # context so gated skills (wordpress-scan, default-creds, nuclei-targeted,
    # correlate) actually fire on what the scanners surfaced. Skill findings
    # from this pass flow through the same triage/validation/normalization.
    _raise_if_cancelled(cancel_event)
    _run_skill_pass_over_findings(report, target_url, already_ran, progress,
                                  cancel_event, profile=profile)

    # Phase 3 - subdomain chained scans: probe discovered live subdomains with
    # the lightweight HTTP scanners (content + waf_detect + http_probe).
    _run_subdomain_chain(report, evidence_store, scanner_instances,
                         kwargs_by_scanner, timeout, progress, cancel_event)

    # Phase 3-2 - origin hunt: if a WAF/CDN was detected, try to find the
    # direct origin IP behind it (P2.4).
    _raise_if_cancelled(cancel_event)
    _run_origin_hunt(report, target_url, progress, cancel_event)

    # Phase 3-3 - report skills: run the deterministic report artifacts
    # (remediation-plan, executive-summary, markdown-report) over the FULL
    # finding set so they are triaged, normalized, and persisted with the scan.
    _raise_if_cancelled(cancel_event)
    _run_report_phase(report, target_url, progress, cancel_event, profile=profile)

    _emit(progress, "step_start", "finalize", "triage · validation · normalization", "chain")
    report.triage = triage(report.findings)

    # Phase 3 - evidence link, validation, normalization.
    raw_blob = "".join(f"{s.name} status={s.status} findings={s.findings_count} "
                       for s in report.statuses)
    evidence_store.add("combined", raw_blob, target_url)

    # Map scanner name -> best-effort command string for tool_command evidence.
    command_by_name = {}
    for s in scanner_instances:
        cmd = getattr(s, "detail", None) or {}
        if isinstance(cmd, dict) and cmd.get("command"):
            command_by_name[s.name] = cmd["command"]
        elif getattr(s, "resolved_path", None):
            command_by_name[s.name] = getattr(s, "resolved_path", "")

    linked: List[RawFinding] = []
    for f in report.findings:
        f.evidence_id = f.evidence_id or evidence_store.add(
            f.scanner, _finding_raw_blob(f), f.url or target_url,
            tool_command=command_by_name.get(f.scanner))
        linked.append(f)
    report.findings = linked
    report.evidences = evidence_store.to_dict()

    validation = validate_findings(report.findings, target_url)
    report.validation = {k: v.to_dict() for k, v in validation.items()}

    evidence_lookup = {eid: ev for eid, ev in evidence_store.items()}
    report.normalized = normalize_all(
        report.findings, scan_id=_scan_id_from(target_url),
        asset_id=_asset_id_for(target_url),
        validation=validation, evidence_lookup=evidence_lookup,
    )

    _emit(progress, "step_finish", "finalize", status="done")

    return report


def _emit(progress, kind, step_id, label=None, phase=None, **event):
    """Helper to fire a progress event (no-op when no callback given)."""
    if progress is None:
        return
    payload = {"kind": kind, "id": step_id}
    if label is not None:
        payload["label"] = label
    if phase is not None:
        payload["phase"] = phase
    payload.update(event)
    progress(payload)


def _emit_findings(progress, rows, step_id) -> None:
    """Stream freshly discovered findings to the live console feed.

    Emits the raw finding dicts as they are produced so the UI can render
    them the moment a skill/scanner completes instead of waiting for the
    whole report."""
    if progress is None or not rows:
        return
    progress({"kind": "findings", "id": step_id,
              "findings": [f.to_dict() for f in rows]})


def _raise_if_cancelled(cancel_event) -> None:
    """Raise ScanCancelled at a step boundary / between steps.

    Never raises when no cancel_event is provided (sync scans are not
    cancellable)."""
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled()


def _run_skill_phases(report: ScannersReport, target_url: str,
                      recon: ReconResult | None,
                      progress=None, cancel_event=None, profile=None) -> set:
    """Run the deterministic skill phases and fold their findings into the report.

    Builds a SkillContext from the recon result, runs the recon → network →
    web phases (exploit/post/report run later, see _run_skill_pass_over_findings
    and _run_report_phase), then appends every skill finding to
    report.findings and records per-skill status.

    Returns the set of skill names that ran (so the post-scanner pass can
    avoid re-running them).
    """
    ran: set[str] = set()
    try:
        from skills.base import SkillContext
        from skills.runner import run_skills

        ctx = _build_skill_context(target_url, recon, report.evidence_store,
                                   profile=profile)
        if not ctx:
            return

        phases: list[str] = ["recon", "network", "web"]
        # NOTE: the exploit phase is deliberately NOT wired here. It runs
        # AFTER the scanners (see _run_skill_pass_over_findings) so the
        # exploit probes consume the full recon + scanner information (ports,
        # technologies, discovered paths, finding-derived gates). The post
        # phase also runs there so correlate/nuclei-targeted evaluate the
        # FULL finding set (including any exploit findings).
        # NOTE: the report phase is always excluded from the skill passes —
        # report skills run once at the very end, after the subdomain chain
        # and origin hunt (see _run_report_phase), over the complete finding
        # set. They emit report artifacts, not target findings.

        for phase in phases:
            for result in run_skills(ctx, phase=phase, on_step=progress,
                                     cancel_event=cancel_event, profile=profile):
                ran.add(result.skill_name)
                report.findings.extend(result.findings)
                _emit_findings(progress, result.findings,
                               f"skill:{result.skill_name}")
                report.statuses.append(ScannerStatus(
                    name=f"skill:{result.skill_name}",
                    status="ran" if result.success else "failed",
                    findings_count=len(result.findings),
                    error=result.error,
                    detail={"phase": phase,
                            "duration_ms": result.duration_ms,
                            "evidence_ids": result.evidence_ids}))
        return ran
    except ScanCancelled:
        raise
    except Exception as exc:  # noqa: BLE001 — skills never break the main scan
        report.statuses.append(ScannerStatus(
            name="skills", status="failed",
            error=f"{type(exc).__name__}: {exc}"))
        return ran


def _run_skill_pass_over_findings(report: ScannersReport, target_url: str,
                                  already_ran: set | None = None,
                                  progress=None, cancel_event=None,
                                  profile=None) -> None:
    """Re-run a focused set of web + exploit + post skills over accumulated findings.

    The first skill pass runs before the scanners, so gated skills can only see
    what recon/root fingerprinting produced. This second pass builds a fresh
    SkillContext, seeds it with the paths and findings the content scanners
    discovered (e.g. /secret/wp-admin), and re-runs only the skills that are
    path/finding-gated and safe to re-evaluate — so WordPress detection and
    default-credential checks finally fire on what was actually probed without
    duplicating every always-on web finding.

    already_ran is the set of skill names the first pass executed; those web
    skills are skipped here to avoid duplicate findings (e.g. a root-level
    WordPress already fingerprinted). The post phase always runs once over the
    full finding set.

    Only the web, exploit, and post phases are re-evaluated here; recon/network
    already ran. The exploit phase runs AFTER the scanners so its probes
    consume the full recon + scanner information, and post (correlate /
    nuclei-targeted) evaluates everything including any exploit findings.
    """
    already_ran = already_ran or set()
    # Skills whose trigger can only become satisfiable once scanner content
    # findings are visible. Re-running the whole web phase would duplicate
    # every always-on web finding, so restrict the second web pass to these.
    # nuclei-targeted runs in the post phase below, not here.
    _REPROBE_SKILLS = {
        "wordpress-scan",
        "default-creds",
    }
    try:
        from app.core.config import settings
        from skills.base import SkillContext
        from skills.runner import run_skills

        ctx = _build_skill_context(target_url, None, report.evidence_store,
                                   profile=profile)
        if not ctx:
            return
        _enrich_context_from_report(ctx, report.findings)

        # Skip any reprobe skill that already fired in pass one.
        reprofile = _SecondPassProfile(
            _REPROBE_SKILLS,
            skip_skills=_REPROBE_SKILLS.intersection(already_ran))
        # Second web pass: only skills gated on scanner-derived conditions.
        for phase in ("web",):
            for result in run_skills(ctx, phase=phase, on_step=progress,
                                     cancel_event=cancel_event,
                                     profile=reprofile):
                report.findings.extend(result.findings)
                _emit_findings(progress, result.findings,
                               f"skill:{result.skill_name}")
                report.statuses.append(ScannerStatus(
                    name=f"skill:{result.skill_name}",
                    status="ran" if result.success else "failed",
                    findings_count=len(result.findings),
                    error=result.error,
                    detail={"phase": f"{phase}-pass2",
                            "duration_ms": result.duration_ms,
                            "evidence_ids": result.evidence_ids}))
        # Exploit phase runs AFTER the scanners here, so its probes fire on
        # the full recon + scanner information (ports, technologies,
        # discovered paths, finding-derived gates). The gate mirrors pass one:
        # a scan profile that explicitly allows exploit skills wins; otherwise
        # the ambient settings toggle decides.
        allow_exploit = settings.ALLOW_EXPLOIT_SKILLS
        if profile is not None:
            allow_exploit = profile.allow_exploit_skills
        if allow_exploit:
            for result in run_skills(ctx, phase="exploit", on_step=progress,
                                     cancel_event=cancel_event,
                                     profile=profile):
                report.findings.extend(result.findings)
                _emit_findings(progress, result.findings,
                               f"skill:{result.skill_name}")
                report.statuses.append(ScannerStatus(
                    name=f"skill:{result.skill_name}",
                    status="ran" if result.success else "failed",
                    findings_count=len(result.findings),
                    error=result.error,
                    detail={"phase": "exploit-pass2",
                            "duration_ms": result.duration_ms,
                            "evidence_ids": result.evidence_ids}))
        # Post phase runs ONCE here over the full finding set (skill findings +
        # scanner findings + any pass-2 web findings). The caller's profile
        # skip_skills (e.g. vm excludes nuclei-targeted) is respected.
        for result in run_skills(ctx, phase="post", on_step=progress,
                                 cancel_event=cancel_event, profile=profile):
            report.findings.extend(result.findings)
            _emit_findings(progress, result.findings,
                           f"skill:{result.skill_name}")
            report.statuses.append(ScannerStatus(
                name=f"skill:{result.skill_name}",
                status="ran" if result.success else "failed",
                findings_count=len(result.findings),
                error=result.error,
                detail={"phase": "post-pass2",
                        "duration_ms": result.duration_ms,
                        "evidence_ids": result.evidence_ids}))
    except ScanCancelled:
        raise
    except Exception as exc:  # noqa: BLE001 — skills never break the main scan
        report.statuses.append(ScannerStatus(
            name="skills-pass2", status="failed",
            error=f"{type(exc).__name__}: {exc}"))


def _run_report_phase(report: ScannersReport, target_url: str,
                      progress=None, cancel_event=None, profile=None) -> None:
    """Run the deterministic report skills over the complete finding set.

    Report skills (remediation-plan, executive-summary, markdown-report) emit
    report artifacts, not target findings. They run AFTER the subdomain chain
    and origin hunt so the executive summary, remediation plan, and markdown
    report capture the full scan surface; their findings flow through the same
    triage/validation/normalization (and persistence) as everything else.
    """
    try:
        from skills.base import SkillContext
        from skills.runner import run_skills

        ctx = _build_skill_context(target_url, None, report.evidence_store,
                                   profile=profile)
        if not ctx:
            return
        _enrich_context_from_report(ctx, report.findings)

        for result in run_skills(ctx, phase="report", on_step=progress,
                                 cancel_event=cancel_event, profile=profile):
            report.findings.extend(result.findings)
            _emit_findings(progress, result.findings,
                           f"skill:{result.skill_name}")
            report.statuses.append(ScannerStatus(
                name=f"skill:{result.skill_name}",
                status="ran" if result.success else "failed",
                findings_count=len(result.findings),
                error=result.error,
                detail={"phase": "report",
                        "duration_ms": result.duration_ms,
                        "evidence_ids": result.evidence_ids}))
    except ScanCancelled:
        raise
    except Exception as exc:  # noqa: BLE001 — skills never break the main scan
        report.statuses.append(ScannerStatus(
            name="skills-report", status="failed",
            error=f"{type(exc).__name__}: {exc}"))


class _SecondPassProfile:
    """Minimal ScanProfile-like object capturing only include_only_skills, so
    the selector's include filter applies without touching environment gates.

    The second skill pass must not re-enable exploits, so allow_exploit_skills
    stays False and no environment assumptions are flipped.
    """

    def __init__(self, names: set, skip_skills: set | None = None) -> None:
        self.include_only_skills = names
        self.skip_skills = list(skip_skills or [])
        self.skip_scanners = []
        self.allow_exploit_skills = False


def _enrich_context_from_report(ctx, findings: list) -> None:
    """Seed a SkillContext with what the scanners discovered.

    Scanners run after skills, so their content-discovery results never reach
    the normal skill pass. This copying phase pulls the URL/path each scanner
    finding was discovered at into `ctx.discovered_paths` (and `ctx.open_ports`)
    so the selector's path-derived conditions (tech_wordpress, admin_path_found,
    login_form_found) and path-aware skills can act on the full surface.
    """
    from urllib.parse import urlparse

    paths: list[str] = []
    seen_urls: set[str] = set()
    technologies: list[str] = []
    for f in findings:
        p = f.path
        if not p:
            p = (f.url or "")
        if p:
            try:
                parsed = urlparse(p)
                if parsed.scheme:
                    # absolute URL -> bare path for consistent matching
                    p = parsed.path or "/"
            except Exception:
                pass
            low = (p or "").lower()
            if low and low not in seen_urls:
                seen_urls.add(low)
                paths.append(p)
        if getattr(f, "port", None):
            if f.port not in ctx.open_ports:
                ctx.open_ports.append(f.port)
        # Surface fingerprint/tech findings so path-gated skills (default-creds
        # tech pairs, etc.) see the same technologies recon would have produced.
        if getattr(f, "scanner_template_id", None) == "tech-identified":
            raw = getattr(f, "raw", {}) or {}
            tech = raw.get("technology") or raw.get("name")
            if tech and tech not in technologies:
                technologies.append(str(tech))

    if paths:
        ctx.discovered_paths.extend(paths)
    if technologies:
        ctx.technologies.extend(technologies)
    # Expose accumulated findings so the selector's finding-type conditions and
    # the correlate skill can consume scanner output alongside skill findings.
    ctx.raw_findings.extend(findings)


def _build_skill_context(target_url: str, recon: ReconResult | None,
                         evidence_store, profile=None) -> "SkillContext | None":
    """Construct a SkillContext from target + recon result (or None to skip)."""
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)
    host = parsed.hostname or ""

    technologies: list[str] = []
    osint: dict = {}
    ip: str | None = None
    if recon:
        if recon.fingerprint:
            technologies = list(recon.fingerprint.technologies)
        if recon.primary_asset and recon.primary_asset.osint:
            osint = recon.primary_asset.osint
        if recon.primary_asset:
            ip = recon.primary_asset.ip
        elif recon.dns:
            ip = recon.dns.primary_ip

    from skills.base import SkillContext
    return SkillContext(
        target_url=target_url,
        host=host,
        ip=ip,
        port=port,
        scheme=scheme,
        technologies=technologies,
        osint=osint,
        authorized=True,
        evidence_store=evidence_store,
        profile=profile,
    )


def _run_one(report: ScannersReport, evidence_store: EvidenceStore,
             scanner, target_url: str, kwargs: dict, progress=None) -> None:
    label = scanner.name
    _emit(progress, "step_start", f"scanner:{scanner.name}", label, "scanner")
    if not scanner.available:
        report.statuses.append(ScannerStatus(
            name=scanner.name, status="unavailable",
            error=f"missing dependency: {scanner.executable!r}"))
        _emit(progress, "step_finish", f"scanner:{scanner.name}",
              status="skipped", findings=0,
              error=f"missing dependency: {scanner.executable!r}")
        return
    try:
        scanner_findings = scanner.scan(target_url, **kwargs)
        report.findings.extend(scanner_findings)
        _emit_findings(progress, scanner_findings, f"scanner:{scanner.name}")
        report.statuses.append(ScannerStatus(
            name=scanner.name, status="ran",
            findings_count=len(scanner_findings),
            warning=getattr(scanner, "warning", None),
            detail=getattr(scanner, "detail", None)))
        _emit(progress, "step_finish", f"scanner:{scanner.name}",
              status="done", findings=len(scanner_findings))
    except base.ScanError as exc:
        report.statuses.append(ScannerStatus(
            name=scanner.name, status="failed", error=str(exc)))
        _emit(progress, "step_finish", f"scanner:{scanner.name}",
              status="failed", error=str(exc))
    except Exception as exc:  # noqa: BLE001 - surfaced, not swallowed
        report.statuses.append(ScannerStatus(
            name=scanner.name, status="failed",
            error=f"{type(exc).__name__}: {exc}"))
        _emit(progress, "step_finish", f"scanner:{scanner.name}",
              status="failed", error=f"{type(exc).__name__}: {exc}")


# Phase 3 (P3.4) — subdomain chained deep scan. Each live subdomain gets a
# REDUCED scanner set to contain scan explosion, plus the lightweight HTTP
# scanners that always provide value.
_SUBCHAIN_TARGETS = {"nmap", "nuclei", "content", "waf_detect", "http_probe"}
_SUBCHAIN_CAP = 10               # max subdomains chained into deep scan
_SUBCHAIN_NMAP_PORTS = "--top-ports 200"
_SUBCHAIN_NUCLEI_TAGS = "tech,config,exposure"


def _run_subdomain_scanner(report: ScannersReport, evidence_store: EvidenceStore,
                           scanner, url: str, kwargs: dict,
                           source_subdomain: str,
                           progress=None) -> List[RawFinding]:
    """Run one scanner on a subdomain and return its findings (never raises)."""
    step_id = f"scanner:{scanner.name}@{source_subdomain}"
    _emit(progress, "step_start", step_id, f"{scanner.name} @ {source_subdomain}",
          "subdomain")
    if not scanner.available:
        report.statuses.append(ScannerStatus(
            name=scanner.name, status="unavailable",
            error=f"missing dependency: {scanner.executable!r}"))
        _emit(progress, "step_finish", step_id, status="skipped",
              error=f"missing dependency: {scanner.executable!r}")
        return []
    try:
        findings = scanner.scan(url, **kwargs)
        report.findings.extend(findings)
        _emit_findings(progress, findings, step_id)
        report.statuses.append(ScannerStatus(
            name=scanner.name, status="ran",
            findings_count=len(findings),
            warning=getattr(scanner, "warning", None),
            detail=getattr(scanner, "detail", None)))
        _emit(progress, "step_finish", step_id, status="done", findings=len(findings))
        return findings
    except base.ScanError as exc:
        report.statuses.append(ScannerStatus(
            name=scanner.name, status="failed", error=str(exc)))
        _emit(progress, "step_finish", step_id, status="failed", error=str(exc))
    except Exception as exc:  # noqa: BLE001 - surfaced, not swallowed
        report.statuses.append(ScannerStatus(
            name=scanner.name, status="failed",
            error=f"{type(exc).__name__}: {exc}"))
        _emit(progress, "step_finish", step_id, status="failed",
              error=f"{type(exc).__name__}: {exc}")
    return []


def _tag_source_subdomain(f: RawFinding, host: str) -> None:
    """Tag a chained finding with its source subdomain."""
    f.raw = dict(f.raw or {})
    f.raw["source_subdomain"] = host


def _run_subdomain_chain(report: ScannersReport, evidence_store: EvidenceStore,
                         scanner_instances: list, kwargs_by_scanner: dict,
                         timeout: int | None, progress=None,
                         cancel_event=None) -> None:
    """Run a controlled, reduced scanner set against live subdomains.

    Subdomains discovered by the subdomains scanner are probed with a bounded
    set (nmap top-200, exposure-only nuclei, content discovery, waf + http
    probe). Findings are tagged with `source_subdomain` so they can be traced
    to the subdomain chain in triage.
    """
    sub_hosts = _find_live_subdomains(report)
    if not sub_hosts:
        _emit(progress, "step_finish", "subdomain_chain", status="skipped",
              error="no live subdomains found")
        return
    _emit(progress, "step_start", "subdomain_chain",
          f"subdomain chained deep-scan ({len(sub_hosts)} host(s))", "subdomain")
    chainable = {s.name: s for s in scanner_instances
                 if s.name in _SUBCHAIN_TARGETS and s.available}
    for host in sub_hosts[:_SUBCHAIN_CAP]:
        _raise_if_cancelled(cancel_event)
        url = f"http://{host}"
        for name, scanner in chainable.items():
            kwargs = dict(kwargs_by_scanner.get(name, {}))
            if name == "nmap":
                kwargs["ports"] = _SUBCHAIN_NMAP_PORTS
            if name == "nuclei":
                kwargs["include_tags"] = _SUBCHAIN_NUCLEI_TAGS
            for f in _run_subdomain_scanner(report, evidence_store, scanner,
                                            url, kwargs, host, progress):
                _tag_source_subdomain(f, host)
    _emit(progress, "step_finish", "subdomain_chain", status="done")


def _find_live_subdomains(report: ScannersReport) -> List[str]:
    """Return live subdomain hostnames reported by the subdomains scanner.

    Only hosts that actually serve content are returned for the chained deep
    scan. A host whose recorded probe status is non-serving (404, 410, 5xx,
    etc.) is skipped — chaining nmap/nuclei/content onto a non-serving
    subdomain wastes the scan budget on a host that presents no reachable
    surface.

    Status codes 401 and 403 ARE chainable — the application exists but
    requires authentication, so there is a surface to scan.
    """
    hosts: List[str] = []
    for f in report.findings:
        if f.scanner == "subdomains":
            h = f.host or f.target or ""
            if not h or "://" in h:
                continue
            status = (f.raw or {}).get("status")
            # Whitelist only chainable status codes:
            #   2xx (OK) — real content
            #   3xx (redirects) — real content behind redirect
            #   401/403 (auth required) — app exists, auth-protected
            # Everything else (404, 410, 5xx, None if we want to be
            # cautious) → skip.
            if isinstance(status, int):
                if (200 <= status < 400) or status in (401, 403):
                    hosts.append(h)
                # else: non-serving status, skip
            elif status is None:
                # No recorded status — include cautiously (the probe
                # may have succeeded but status wasn't captured).
                hosts.append(h)
    return sorted(set(hosts))


def _run_origin_hunt(report: ScannersReport, target_url: str, progress=None,
                     cancel_event=None) -> None:
    """Run the origin-IP hunt when a WAF/CDN was detected (P2.4).

    Origin hunt only pays off behind a WAF; it is skipped otherwise. Any
    found origin findings feed the same triage as the rest of the scan.
    """
    waf_metadata = None
    for f in report.findings:
        if f.scanner == "waf_detect":
            waf_metadata = (f.raw or {}).get("waf_metadata") or {}
            break
    if not waf_metadata:
        _emit(progress, "step_finish", "origin_hunt", status="skipped",
              error="no WAF/CDN detected")
        return
    _emit(progress, "step_start", "origin_hunt", "origin hunt (behind WAF)", "chain")
    try:
        _raise_if_cancelled(cancel_event)
        from pipeline.recon.origin_hunt import run_origin_hunt
        _, origin_findings = run_origin_hunt(target_url, waf_metadata)
    except Exception as exc:  # noqa: BLE001 - origin hunt is best-effort
        report.statuses.append(ScannerStatus(
            name="origin_hunt", status="failed", error=f"{type(exc).__name__}: {exc}"))
        _emit(progress, "step_finish", "origin_hunt", status="failed",
              error=f"{type(exc).__name__}: {exc}")
        return
    if origin_findings:
        report.findings.extend(origin_findings)
        _emit_findings(progress, origin_findings, "origin_hunt")
        report.statuses.append(ScannerStatus(
            name="origin_hunt", status="ran",
            findings_count=len(origin_findings)))
    _emit(progress, "step_finish", "origin_hunt", status="done",
          findings=len(origin_findings))


def _order_subdomain_first(scanner_instances: list) -> list:
    """Reorder scanner instances so the subdomains scanner runs before others.

    The subdomain chain (deep scan of discovered live subdomains) depends on
    the subdomains scanner having run already; running it first lets the chain
    probe the widest frontier without waiting for the whole set.
    """
    if not scanner_instances:
        return scanner_instances
    sub = [s for s in scanner_instances if s.name == "subdomains"]
    rest = [s for s in scanner_instances if s.name != "subdomains"]
    return sub + rest


def _osint_findings_from_recon(recon: ReconResult | None) -> List[RawFinding]:
    """Rehydrate passive OSINT findings carried by the ReconResult.

    `run_recon` attaches OSINT-originated RawFinding.to_dict() rows to
    `ReconResult.osint_findings`; this reconstructs them into RawFinding
    objects so the scan report treats them like any other finding.
    """
    if not recon or not recon.osint_findings:
        return []
    out: List[RawFinding] = []
    for d in recon.osint_findings:
        if not isinstance(d, dict):
            continue
        try:
            out.append(RawFinding(**{k: v for k, v in d.items()
                                     if k in RawFinding.__dataclass_fields__}))
        except TypeError:
            continue
    return out


def _finding_raw_blob(f: RawFinding) -> str:
    try:
        return f"{f.scanner}/{f.scanner_template_id} sev={f.severity} " \
               f"target={f.target} host={f.host} port={f.port} " \
               f"url={f.url} path={f.path} desc={f.description}\n" \
               f"raw={f.raw}"
    except Exception:
        return str(f.to_dict())


def _scan_id_from(target: str) -> str:
    import hashlib
    return hashlib.md5(target.encode()).hexdigest()[:12]


def _asset_id_for(target: str) -> str:
    """Stable asset id derived from the canonical scan id + target URL.

    The canonical Finding model requires a non-empty asset_id; derive it the
    same way the rest of the pipeline does (digest of scan_id:target) so
    normalized findings from the reference scanner pipeline satisfy the model.
    """
    import hashlib
    digest = hashlib.sha256(
        f"{_scan_id_from(target)}:{target}".encode()
    ).hexdigest()[:16]
    return f"asset-{digest}"


def _derive_url(target: str, recon: ReconResult | None) -> str:
    """Return a best-effort URL to scan from target + prior recon."""
    if "://" in target or target.startswith(("http://", "https://")):
        return target
    if recon and recon.live and recon.live.url:
        return recon.live.url
    return f"http://{target}"


def _build_scanner_kwargs(timeout: int | None, ports: str | None,
                          cancel_event=None, profile=None) -> dict[str, dict]:
    """Filter optional scan parameters by what each scanner's scan() accepts.
    A scanner that takes neither arg simply gets {}."""
    imports: dict[str, type] = {
        "nmap": nmap_scanner.NmapScanner,
        "nuclei": nuclei_scanner.NucleiScanner,
        "http_probe": http_probe.HttpProbeScanner,
        "nmap_tls": nmap_tls.NmapTlsScanner,
        "subdomains": subdomains_httpx.SubdomainHttpxScanner,
        "content": content_httpx.ContentHttpxScanner,
        "waf_detect": waf_detect.WafDetectScanner,
    }
    # Web targets get a fast --top-ports deep-scan; VM/CTF profiles keep full
    # 65535-port coverage so every port is enumerated on an isolated host.
    nmap_start_plan = None
    if profile is not None:
        nmap_start_plan = ("-p-" if profile.nmap_full_port
                           else "--top-ports 1000")
    kwargs_by_scanner: dict[str, dict] = {}
    for name, cls in imports.items():
        params = set(_scan_params(cls))
        kwargs: dict[str, object] = {}
        if timeout is not None and "timeout" in params:
            kwargs["timeout"] = timeout
        if ports is not None and "ports" in params:
            kwargs["ports"] = ports
        if nmap_start_plan is not None and "start_plan" in params and name == "nmap":
            kwargs["start_plan"] = nmap_start_plan
        if cancel_event is not None and "cancel_event" in params:
            kwargs["cancel_event"] = cancel_event
        kwargs_by_scanner[name] = kwargs
    return kwargs_by_scanner


def _scan_params(scanner_cls: type) -> list[str]:
    import inspect
    import itertools

    sig = inspect.signature(scanner_cls.scan)
    return list(itertools.islice(sig.parameters, 1, None))


__all__ = ["run_scanners", "ScannersReport", "ScannerStatus", "base", "RawFinding"]