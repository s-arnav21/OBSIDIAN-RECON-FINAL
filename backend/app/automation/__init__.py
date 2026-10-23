"""Automation registry — MITRE technique scripts the LLM can select and run.

Mirrors the ``skills`` registry pattern: scripts self-register via
``@technique`` and are auto-imported by :func:`load_all_techniques`. The catalog
is fed to the LLM planner so it can reason about which technique a finding
unlocks and what capability each technique grants.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, List

from app.automation.base import (
    AutomationContext,
    TechniqueResult,
    TechniqueScript,
    TechniqueStatus,
)

_REGISTRY: Dict[str, TechniqueScript] = {}
_LOADED = False


def register(cls: type) -> type:
    """Class decorator that registers a technique script instance."""
    instance = cls()
    if not isinstance(instance, TechniqueScript):
        raise TypeError("registered automation scripts must subclass TechniqueScript")
    if not instance.technique_id:
        raise ValueError(f"{cls.__name__} must declare a technique_id")
    _REGISTRY[instance.technique_id] = instance
    return cls


# Public alias matching the skills registry naming.
technique = register


def get_technique(technique_id: str) -> TechniqueScript:
    load_all_techniques()
    return _REGISTRY[technique_id]


def has_technique(technique_id: str) -> bool:
    load_all_techniques()
    return technique_id in _REGISTRY


def all_techniques() -> List[TechniqueScript]:
    load_all_techniques()
    return [_REGISTRY[key] for key in sorted(_REGISTRY)]


def technique_catalog() -> List[dict]:
    """Bounded, planner-safe catalogue of registered techniques."""
    return [script.describe() for script in all_techniques()]


def technique_tool_catalog() -> List[dict]:
    """Planner-safe tool entries so the LLM can select ``technique:<id>`` tools.

    Mirrors the fields the agent executor's tool catalog exposes so the same
    planner prompt builder can describe techniques and tools uniformly.
    """
    catalog: List[dict] = []
    for script in all_techniques():
        catalog.append({
            "tool_id": f"technique:{script.technique_id}",
            "name": script.name,
            "description": script.description,
            "category": "mitre-technique",
            "available": True,
            "vulnerability_types": list(script.vuln_types),
            "requires_all": list(script.requires_all),
            "requires_any": list(script.requires_any),
            "provides": list(script.provides),
            "automatic_allowed": script.automatic_allowed,
            "allowed_options": list(script.allowed_options),
        })
    return catalog


def load_all_techniques() -> None:
    """Auto-import every module under ``app.automation.scripts`` once."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    package = importlib.import_module("app.automation.scripts")
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        importlib.import_module(f"app.automation.scripts.{module_name}")


__all__ = [
    "register",
    "technique",
    "get_technique",
    "has_technique",
    "all_techniques",
    "technique_catalog",
    "technique_tool_catalog",
    "load_all_techniques",
    "TechniqueScript",
    "TechniqueResult",
    "TechniqueStatus",
    "AutomationContext",
]
