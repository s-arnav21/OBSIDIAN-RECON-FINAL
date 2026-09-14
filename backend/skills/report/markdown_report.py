"""Deterministic markdown report generator (SKILL-REP03).

Always runs (requires_all: []). Builds a human-readable Markdown report
document from every raw finding in `ctx.raw_findings`, grouped by severity,
with a header containing target, host, date, and aggregate counts. Emits a
`markdown-report` finding whose `raw` carries the full document (including
a `markdown` key so the UI/DB can render or export it).

Pure function of the finding set — no LLM.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium",
           "low": "Low", "info": "Info"}


def _host_of(f: RawFinding) -> str:
    for c in (f.host, f.target):
        if c and "://" not in str(c):
            return str(c)
    return str(f.host or f.target or "?")


def _render_markdown(ctx: SkillContext, fs: list[RawFinding]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    lines.append(f"# Obsidian Recon Report — {ctx.host}")
    lines.append("")
    lines.append(f"- **Target:** `{ctx.target_url}`")
    lines.append(f"- **Host:** `{ctx.host}`")
    lines.append(f"- **Date:** {now}")
    lines.append(f"- **Total findings:** {len(fs)}")
    sev = {s: 0 for s in _SEVERITY_ORDER}
    for f in fs:
        if (f.severity or "info").lower() in sev:
            sev[(f.severity or "info").lower()] += 1
    lines.append("- **Severity:** "
                 + ", ".join(f"{_LABELS[s]} {sev[s]}" for s in _SEVERITY_ORDER))
    if ctx.open_ports:
        lines.append("- **Open ports:** " + ", ".join(map(str, sorted(ctx.open_ports))))
    if ctx.technologies:
        lines.append("- **Technologies:** " + ", ".join(sorted(set(ctx.technologies))))
    lines.append("")

    for sev in _SEVERITY_ORDER:
        bucket = [f for f in fs if (f.severity or "info").lower() == sev]
        if not bucket:
            continue
        lines.append(f"## {_LABELS[sev]} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            host = _host_of(f)
            endpoint = f.matched_at or f.url or host
            lines.append(f"- **[{f.scanner_template_id}]** {f.description or '—'} "
                         f"`{endpoint}` *(scanner: {f.scanner})*")
        lines.append("")

    lines.append("---")
    lines.append("_Generated deterministically by Obsidian Recon._")
    return "\n".join(lines)


@register
class MarkdownReportSkill(Skill):
    """Render a human-readable Markdown report of all findings."""

    name = "markdown-report"
    display_name = "Markdown report"
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
        md = _render_markdown(ctx, fs)
        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="markdown-report",
            vulnerability_type="report-markdown",
            target=ctx.target_url, host=ctx.host,
            severity="info",
            url=ctx.target_url,
            description=f"Markdown report for {ctx.host} "
                        f"({len(fs)} findings).",
            raw={"markdown": md},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {"report": {"markdown": md}}})
