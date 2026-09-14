"""Skill Registry — auto-imports every skill module so @register fires."""
import importlib
import pkgutil
from pathlib import Path

from .base import Skill

_REGISTRY: dict[str, Skill] = {}


def register(cls):
    """Decorator to register a skill class."""
    instance = cls()
    _REGISTRY[instance.name] = instance
    return cls


def get_skill(name: str) -> Skill:
    return _REGISTRY[name]


def all_skills() -> list[Skill]:
    return list(_REGISTRY.values())


def skills_by_category(category) -> list[Skill]:
    return [s for s in _REGISTRY.values()
            if s.category == category]


def load_all_skills():
    """Auto-import all skill modules so @register decorators fire."""
    skills_dir = Path(__file__).parent
    for subdir in ["recon", "web", "network", "exploit",
                   "post", "report"]:
        pkg_path = skills_dir / subdir
        if not pkg_path.exists():
            continue
        pkg_name = f"skills.{subdir}"
        for _, module_name, _ in pkgutil.iter_modules([str(pkg_path)]):
            importlib.import_module(f"{pkg_name}.{module_name}")


__all__ = [
    "Skill",
    "SkillCategory",
    "SkillContext",
    "SkillResult",
    "register",
    "get_skill",
    "all_skills",
    "skills_by_category",
    "load_all_skills",
]