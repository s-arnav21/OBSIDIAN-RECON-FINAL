"""Deterministic executive summary generation (SKILL-REP01).

Always runs (requires_all: []). Consumes the accumulated `ctx.raw_findings`
and emits a single `executive-summary` finding (a report artifact) plus a
machine-readable summary nested under `ctx.osint.report.summary`.

Everything is a pure function of the finding set:
  - total finding count + per-severity counts
  - top vulnerability categories by count (canonical types)
  - open ports, detected technologies, and WAF presence for context
  - a short, templated plain-language posture statement

No LLM — identical input always yields identical output.
"""
from __future__ import annotations

from collections import Counter

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _severity_counts(fs: list[RawFinding]) -> dict[str, int]:
    counts = Counter(
        f.severity for f in fs if f.severity in _SEVERITY_RANK)
    return {sev: counts.get(sev, 0) for sev in _SEVERITY_ORDER}


def _canonical_type_of(f: RawFinding) -> str:
    try:
        from pipeline.normalize import _canonical_type
        return _canonical_type(f)
    except Exception:  # noqa: BLE001
        return (f.vulnerability_type or f.scanner_template_id or "unknown").lower()


def _top_categories(fs: list[RawFinding], n: int = 6) -> list[dict]:
    cats: Counter[str] = Counter(_canonical_type_of(f) for f in fs)
    return [{"type": t, "count": c} for t, c in cats.most_common(n)]


def _posture(counts: dict[str, int]) -> dict:
    if counts["critical"]:
        level, verdict = "critical", ("Immediate remediation is required: the target "
                                       "presents critical-severity vulnerabilities that "
                                       "are likely directly exploitable.")
    elif counts["high"]:
        level, verdict = "high", ("High-risk findings were discovered that offer a "
                                   "credible path to compromise; prioritize remediation.")
    elif counts["medium"]:
        level, verdict = "moderate", ("The target shows a moderate risk profile with "
                                      "several medium-severity exposures to address.")
    elif counts["low"]:
        level, verdict = "low", ("Low-risk findings were identified; the target's "
                                 "exposure is limited and largely informational.")
    else:
        level, verdict = "none", ("No findings were recorded; no issues were observed "
                                  "against this target in the current scan.")
    return {"level": level, "verdict": verdict}


@register
class ExecutiveSummarySkill(Skill):
    """Produce a deterministic executive summary of the scan findings."""

    name = "executive-summary"
    display_name = "Executive summary"
    category = SkillCategory.REPORT
    version = "1.0"
    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 5
    max_requests = 0

    def should_run(self, ctx: SkillContext) -> bool:
        return True

    def run(self, ctx: SkillContext) -> SkillResult:
        fs = list(ctx.raw_findings)
        counts = _severity_counts(fs)
        posture = _posture(counts)

        summary = {
            "total_findings": len(fs),
            "by_severity": counts,
            "top_categories": _top_categories(fs),
            "open_ports": sorted(set(ctx.open_ports)),
            "technologies": sorted(set(ctx.technologies)),
            "waf_detected": ctx.waf_detected,
            "waf_provider": ctx.waf_provider,
            "subdomains": len(ctx.subdomains),
            "posture": posture,
        }

        desc = (f"{ctx.host}: {counts['critical']} critical, {counts['high']} high, "
                f"{counts['medium']} medium, {counts['low']} low, {counts['info']} info "
                f"({len(fs)} total). Posture: {posture['level']}.")

        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="executive-summary",
            vulnerability_type="report-summary",
            target=ctx.target_url, host=ctx.host,
            severity="info",
            url=ctx.target_url,
            description=desc,
            raw={"summary": summary},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {"report": {"summary": summary}}})
