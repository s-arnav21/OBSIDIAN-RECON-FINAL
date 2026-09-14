"""Deterministic remediation plan generator (SKILL-REP02).

Always runs (requires_all: []). Groups the accumulated raw findings by
canonical vulnerability type, orders them by severity, and attaches KB-driven
remediation guidance plus the affected endpoints/hosts. Emits a
`remediation-plan` report finding plus a machine-readable plan under
`ctx.osint.report.remediation`.

Pure function of the finding set and the normalize-layer KB — no LLM.
"""
from __future__ import annotations

from collections import OrderedDict

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
                  "unknown": 0}


def _canonical_type_of(f: RawFinding) -> str:
    try:
        from pipeline.normalize import _canonical_type, _kb_for
        return _canonical_type(f)
    except Exception:  # noqa: BLE001
        return (f.vulnerability_type or f.scanner_template_id or "unknown").lower()


def _kb_for_type(t: str) -> dict:
    try:
        from pipeline.normalize import _kb_for
        return _kb_for(t)
    except Exception:  # noqa: BLE001
        return {}


def _label_for(t: str) -> str:
    kb = _kb_for_type(t)
    label = kb.get("label")
    if label and label.lower() != "unclassified finding":
        return label
    return t.replace("-", " ").replace("_", " ").title()


def _build_plan(fs: list[RawFinding]) -> list[dict]:
    groups: "OrderedDict[str, dict]" = OrderedDict()
    for f in fs:
        t = _canonical_type_of(f)
        g = groups.setdefault(t, {
            "type": t,
            "label": _label_for(t),
            "severity": "info",
            "count": 0,
            "endpoints": [],
        })
        sev = (f.severity or "info").lower()
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(g["severity"], 0):
            g["severity"] = sev if sev in _SEVERITY_RANK else "info"
        g["count"] += 1
        endpoint = f.matched_at or f.url or f.target
        if endpoint and endpoint not in g["endpoints"]:
            g["endpoints"].append(endpoint)

    plan = []
    for g in groups.values():
        kb = _kb_for_type(g["type"])
        g["cwe"] = kb.get("cwe")
        g["owasp"] = kb.get("owasp")
        g["remediation"] = kb.get("remediation") or "Manual review required."
        plan.append(g)

    plan.sort(key=lambda g: _SEVERITY_RANK.get(g["severity"], 0), reverse=True)
    return plan


@register
class RemediationPlanSkill(Skill):
    """Produce a severity-ordered remediation plan from the findings."""

    name = "remediation-plan"
    display_name = "Remediation plan"
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
        plan = _build_plan(fs)

        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="remediation-plan",
            vulnerability_type="report-remediation",
            target=ctx.target_url, host=ctx.host,
            severity="info",
            url=ctx.target_url,
            description=f"Remediation plan for {ctx.host}: {len(plan)} affected "
                        f"issue groups across {len(fs)} findings.",
            raw={"remediation": plan},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {"report": {"remediation": plan}}})
