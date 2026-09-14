"""Skill ABC, SkillContext, and SkillResult — the foundation of Obsidian Recon
skills. A Skill is a self-contained, deterministic module that performs one
unit of reconnaissance/scanner/exploitation work against a target and returns
findings plus context updates.

No LLM is used: each skill decides whether to run via the deterministic
`should_run()` check and executes via `run()`. The selector (selector.py)
chooses WHICH skills to invoke using deterministic condition tokens; this file
just defines the contract every skill implements.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class SkillCategory(str, Enum):
    RECON    = "recon"      # passive info gathering
    WEB      = "web"        # web application surface
    NETWORK  = "network"    # ports, services, protocols
    EXPLOIT  = "exploit"    # exploitation attempts
    POST     = "post"       # post-discovery analysis
    REPORT   = "report"     # output + formatting


@dataclass
class SkillContext:
    """Everything a skill knows about the current target.

    Populated progressively as the pipeline runs. Each skill merges its
    context_updates back into this shared object in the SkillRunner, so later
    skills see the results of earlier ones.
    """
    target_url: str
    host: str
    ip: Optional[str] = None
    port: int = 443
    scheme: str = "https"

    # Populated progressively as pipeline runs
    open_ports: list[int] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    waf_detected: bool = False
    waf_provider: Optional[str] = None
    subdomains: list[str] = field(default_factory=list)
    discovered_paths: list[str] = field(default_factory=list)
    param_candidates: list = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    osint: dict = field(default_factory=dict)
    raw_findings: list = field(default_factory=list)
    evidence_store: Any = None

    # Metadata
    scan_id: str = ""
    authorized: bool = False
    cancel_event: Any = None  # Optional[threading.Event] — skills should poll it
    profile: Any = None       # Optional[ScanProfile] — profile-driven behavior


@dataclass
class SkillResult:
    """What a skill returns."""
    skill_name: str
    success: bool
    findings: list        # list[RawFinding]
    evidence_ids: list[str] = field(default_factory=list)
    context_updates: dict = field(default_factory=dict)
    # context_updates: keys from SkillContext that this skill
    # populated — e.g. {"open_ports": [22, 80, 443]}
    # Pipeline merges these back into the shared SkillContext
    error: Optional[str] = None
    duration_ms: int = 0


class Skill(ABC):
    """Base class for all Obsidian Recon skills."""

    # --- Identity ---
    name: str = ""           # unique slug: "dns-zone-transfer"
    display_name: str = ""   # human label: "DNS Zone Transfer"
    category: SkillCategory = SkillCategory.RECON
    version: str = "1.0"

    # --- Trigger conditions ---
    # All conditions in requires_all must be true to auto-trigger
    requires_all: list[str] = []
    # At least one condition in requires_any must be true
    requires_any: list[str] = []
    # Conditions that block this skill from running
    conflicts_with: list[str] = []

    # Condition tokens (used in requires_*/conflicts_with):
    # "waf_detected", "port_80_open", "port_443_open",
    # "port_22_open", "port_21_open", "port_445_open",
    # "tech_wordpress", "tech_laravel", "tech_django",
    # "tech_spring", "tech_php", "tech_aspnet", "tech_node",
    # "subdomain_found", "admin_path_found", "api_found",
    # "graphql_found", "login_form_found", "sql_error_found",
    # "js_secret_found", "git_exposed", "env_exposed",
    # "origin_ip_found", "high_finding_exists",
    # "critical_finding_exists"

    # --- Execution config ---
    timeout_seconds: int = 60
    max_requests: int = 100
    requires_tools: list[str] = []  # external binaries needed

    @abstractmethod
    def should_run(self, ctx: SkillContext) -> bool:
        """Return True if this skill should run given current context.
           Deterministic check — no LLM needed."""
        raise NotImplementedError

    @abstractmethod
    def run(self, ctx: SkillContext) -> SkillResult:
        """Execute the skill and return findings + context updates."""
        raise NotImplementedError

    def describe(self) -> dict:
        """Returns skill metadata (name, display_name, category, version)."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "category": self.category.value,
            "requires_all": self.requires_all,
            "requires_any": self.requires_any,
            "conflicts_with": self.conflicts_with,
            "description": self.__doc__ or "",
        }