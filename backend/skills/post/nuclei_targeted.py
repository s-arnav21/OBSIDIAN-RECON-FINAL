"""Targeted nuclei run — technology and severity-scoped templates.

Gated on `tech_wordpress` / `tech_laravel` / `tech_spring` / `tech_django` /
`high_finding_exists` and requires the `nuclei` binary. One run per target:

  - `-tags` derived from detected technologies (wordpress, laravel,
    spring/springboot, django)
  - `-severity high,critical` (all severities when a high-severity finding
    already exists) plus generic web tags

Nuclei's JSONL output is parsed line-by-line into `nuclei-<template-id>`
RawFindings with severity mapped to the platform's levels.
"""
from __future__ import annotations

import json
import subprocess
from typing import List, NamedTuple, Optional
from urllib.parse import urlsplit

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

_SEVERITY_MAP = {"info": "info", "low": "low", "medium": "medium",
                 "high": "high", "critical": "critical"}
_TECH_TAGS = {"tech_wordpress": "wordpress", "tech_laravel": "laravel",
              "tech_spring": "spring,springboot", "tech_django": "django"}
_GENERIC_TAGS = "sqli,xss,lfi,rce,ssrf,exposure,tech"
_TIMEOUT = 600


class NucleiHit(NamedTuple):
    template_id: str
    name: str
    severity: str
    matcher: str
    host: str


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlsplit(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _conditions(ctx: SkillContext) -> set[str]:
    from skills.selector import derive_conditions
    return derive_conditions(ctx)


def _nuclei_command(target: str, tags: str, severity: str) -> List[str]:
    return [
        "nuclei", "-u", target, "-tags", tags, "-severity", severity,
        "-jsonl", "-silent", "-no-color", "-nc",
    ]


def _run_nuclei(args: List[str], timeout: int) -> str:
    proc = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout,
        check=False)
    return (proc.stdout or "") + (proc.stderr or "")


def _parse_jsonl(raw: str) -> List[NucleiHit]:
    hits: List[NucleiHit] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = obj.get("template-id") or obj.get("templateID")
        info = obj.get("info") or {}
        severity = _SEVERITY_MAP.get(info.get("severity", ""), "info")
        hits.append(NucleiHit(
            template_id=tid or "unknown",
            name=(info.get("name") or tid)[:140],
            severity=severity,
            matcher=(obj.get("matcher-name") or "")[:80],
            host=obj.get("host") or (obj.get("matched-at") or ""),
        ))
    return hits


@register
class NucleiTargetedSkill(Skill):
    """Run nuclei scoped to detected technologies and severity."""

    name = "nuclei-targeted"
    display_name = "Nuclei targeted scan"
    category = SkillCategory.POST
    version = "1.0"

    requires_any: list[str] = ["tech_wordpress", "tech_laravel",
                               "tech_spring", "tech_django",
                               "high_finding_exists"]
    requires_tools: list[str] = ["nuclei"]

    timeout_seconds = _TIMEOUT + 30
    max_requests = 1

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"nuclei_scan": "no-target"}})

        conds = _conditions(ctx)
        tags = [tag for cond, tag in _TECH_TAGS.items() if cond in conds]
        if not tags:
            tags = [_GENERIC_TAGS]
        severity = "all" if "high_finding_exists" in conds else "high,critical"

        try:
            raw = _run_nuclei(
                _nuclei_command(ctx.target_url, ",".join(tags), severity),
                _TIMEOUT)
        except Exception as e:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"nuclei_scan": "failed",
                                           "nuclei_error": str(e)[:160]}})

        hits = _parse_jsonl(raw)
        if not hits:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"nuclei_scan": "clean",
                                           "nuclei_tags": ",".join(tags)}})

        findings: List[RawFinding] = []
        seen: set[str] = set()
        for hit in hits:
            if hit.template_id in seen:
                continue
            seen.add(hit.template_id)
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id=f"nuclei-{hit.template_id}",
                vulnerability_type="nuclei",
                target=hit.host or ctx.target_url, host=host,
                severity=hit.severity,
                url=hit.host or ctx.target_url,
                description=hit.name,
                raw={"template_id": hit.template_id, "name": hit.name,
                     "matcher": hit.matcher, "host": hit.host},
            ))

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "nuclei_templates": sorted(seen),
                "nuclei_tags": ",".join(tags),
                "nuclei_scan": "findings"}})