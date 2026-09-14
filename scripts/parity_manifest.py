"""Runtime parity manifest for validating the skills/scanner sync.

Run this from inside a project's backend/ directory (it imports from the
cwd). It dumps the same structural manifest from each project so the two
outputs can be diffed:

    cd <project>/backend && python /path/to/parity_manifest.py

Usage differences that are EXPECTED and harmless:
  - comment/whitespace differences are invisible (we dump values, not source)
  - the old project may print extra config fields that the new project
    defines elsewhere; compare only the keys present in both.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.getcwd())


def skill_manifest() -> list[dict]:
    from skills import load_all_skills, all_skills
    load_all_skills()
    rows = []
    for skill in sorted(all_skills(), key=lambda s: s.name):
        rows.append({
            "name": skill.name,
            "category": skill.category.value,
            "requires_all": sorted(skill.requires_all),
            "requires_any": sorted(skill.requires_any),
            "conflicts_with": sorted(skill.conflicts_with),
            "version": skill.version,
        })
    return rows


def scanner_manifest() -> list[dict]:
    from pipeline.scanner import base
    return sorted(base.available_scanners())


def profile_manifest() -> list[dict]:
    from app.core.profiles import PROFILES, profile_names
    rows = []
    for name in profile_names():
        p = PROFILES[name]
        rows.append({
            "name": name,
            "include_only_skills": sorted(p.include_only_skills or []),
            "skip_skills": sorted(p.skip_skills or []),
            "skip_scanners": sorted(p.skip_scanners or []),
            "exploit_phase_enabled": bool(getattr(p, "exploit_phase_enabled", None)),
            "wordlist_profile": getattr(p, "wordlist_profile", None),
            "root_available": bool(getattr(p, "root_available", None)),
            "nmap_timing": getattr(p, "nmap_timing", None),
        })
    return rows


def config_manifest() -> dict:
    from app.core.config import settings
    fields = [
        "AUTHORIZATION_RESTRICTED", "ALLOWED_PRIVATE_RANGES",
        "ALLOW_EXPLOIT_SKILLS", "NMAP_SCAN_TIMEOUT", "NMAP_MIN_RATE",
        "MAX_SKILL_TIMEOUT",
    ]
    return {f: getattr(settings, f, "<missing>") for f in fields}


def normalize_manifest() -> dict:
    from pipeline.normalize import _ALIASES
    return dict(sorted(_ALIASES.items()))


def main() -> None:
    manifest = {
        "project": os.getcwd(),
        "skills": skill_manifest(),
        "scanners": list(scanner_manifest()),
        "profiles": profile_manifest(),
        "config": config_manifest(),
        "normalize_aliases": normalize_manifest(),
    }
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True, default=str)
    print()


if __name__ == "__main__":
    main()