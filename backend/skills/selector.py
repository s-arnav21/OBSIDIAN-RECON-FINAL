"""Deterministic skill selector.

Uses condition tokens derived from the SkillContext to decide which skills to
run and in what order. Selection is fully deterministic — no LLM is involved.
"""
import os
import shutil
import sys

from .base import Skill, SkillContext
from . import all_skills


def derive_conditions(ctx: SkillContext) -> set[str]:
    """Convert SkillContext state into condition tokens."""
    conditions = set()

    # Port conditions
    for port in ctx.open_ports:
        conditions.add(f"port_{port}_open")

    # Technology conditions
    for tech in ctx.technologies:
        t = tech.lower()
        if "wordpress" in t: conditions.add("tech_wordpress")
        if "laravel"   in t: conditions.add("tech_laravel")
        if "django"    in t: conditions.add("tech_django")
        if "spring"    in t: conditions.add("tech_spring")
        if "php"       in t: conditions.add("tech_php")
        if "asp"       in t: conditions.add("tech_aspnet")
        if "node"      in t or "express" in t:
            conditions.add("tech_node")
        if "iis"       in t: conditions.add("tech_iis")
        if "nginx"     in t: conditions.add("tech_nginx")
        if "apache"    in t: conditions.add("tech_apache")

    # State conditions
    if ctx.waf_detected:         conditions.add("waf_detected")
    if ctx.subdomains:           conditions.add("subdomain_found")
    if ctx.osint.get("origin_ip"):
        conditions.add("origin_ip_found")

    # Finding-derived conditions
    finding_types = {getattr(f, "scanner_template_id", None)
                     for f in ctx.raw_findings}

    # Path-derived technology conditions: a scanner-probed WordPress surface
    # (wp-admin, wp-content, wp-includes, xmlrpc.php, wp-login.php, wp-config)
    # is enough to treat the target as WordPress even when the stack
    # fingerprint on the root page (e.g. the app lives under /secret/) found
    # nothing.
    if any(_wp_path_token in (p or "").lower()
           for p in ctx.discovered_paths
           for _wp_path_token in ("wp-admin", "wp-content", "wp-includes",
                                  "wp-login", "wp-json", "xmlrpc", "wp-config")):
        conditions.add("tech_wordpress")

    if any("admin" in p for p in ctx.discovered_paths):
        conditions.add("admin_path_found")
    if any("api" in p or "graphql" in p
           for p in ctx.discovered_paths):
        conditions.add("api_found")
    if any("graphql" in p for p in ctx.discovered_paths):
        conditions.add("graphql_found")
    if any(".asp" in p.lower() for p in ctx.discovered_paths):
        conditions.add("asp_page_found")
    if "login-form-found"   in finding_types:
        conditions.add("login_form_found")
    if "sqli-error-signal"  in finding_types:
        conditions.add("sql_error_found")
    if "js-secret-detected" in finding_types:
        conditions.add("js_secret_found")
    if "git-exposed"        in finding_types:
        conditions.add("git_exposed")
    if any(getattr(f, "severity", "") in ("critical", "high")
           for f in ctx.raw_findings):
        conditions.add("high_finding_exists")

    return conditions


def select_skills(ctx: SkillContext,
                  phase: str = "all",
                  profile=None) -> list[Skill]:
    """Return ordered list of skills to run given current context.

    profile: optional ScanProfile. Its include_only_skills restricts the
    candidate set and skip_skills removes skills outright (both applied
    before the condition/tool checks, so a skipped skill is never run no
    matter what conditions its prerequisites imply).
    """
    conditions = derive_conditions(ctx)
    runnable = []

    for skill in all_skills():
        # Phase filter
        if phase != "all" and skill.category.value != phase:
            continue

        # Profile filter — deterministic include/skip applied up-front so a
        # profile can drop skills that assume internet/DNS without relying on
        # the skill author to implement an environment check.
        if profile is not None:
            if profile.include_only_skills and skill.name not in profile.include_only_skills:
                continue
            if skill.name in profile.skip_skills:
                continue

        # Check tool availability
        if not _tools_available(skill.requires_tools):
            continue

        # Check conflicts
        if any(c in conditions for c in skill.conflicts_with):
            continue

        # Check requirements
        all_met = all(r in conditions for r in skill.requires_all)
        any_met = (not skill.requires_any or
                   any(r in conditions for r in skill.requires_any))

        if all_met and any_met:
            if skill.should_run(ctx):
                runnable.append(skill)

    # Execution order: recon → network → web → post
    ORDER = ["recon", "network", "web", "exploit", "post", "report"]
    runnable.sort(key=lambda s: ORDER.index(s.category.value)
                                if s.category.value in ORDER else 99)
    return runnable


def _tools_available(tools: list[str]) -> bool:
    for tool in tools:
        candidates = [
            shutil.which(tool),
            os.path.join(sys.prefix, "bin", tool),
            f"/usr/bin/{tool}",
            f"/usr/local/bin/{tool}",
        ]
        if not any(p and os.path.isfile(p) for p in candidates):
            return False
    return True