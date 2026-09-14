"""Shared scanner interface and registry.

Every scanner (Nmap, Nuclei, built-in probes, future webhook/scanner
integrations) implements the same `scan()` interface and returns a list of
RawFinding objects. The normalizer layer then converts these into canonical
Finding objects, decoupling scanner identity from validation logic.
"""
from __future__ import annotations

import os
import shutil
import sys
from abc import ABC, abstractmethod
from typing import Callable, List, Optional

from app.models.scanner import RawFinding

# Ordered search paths for external tool resolution (BUG 1). Handled in
# priority order so a tool that exists on PATH but is NOT executable is not
# silently preferred over a valid installed location.
_SEARCH_PATHS = (
    "/usr/bin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt/homebrew/bin",
)

# Module-level cache so repeated `available`/`resolved_path` lookups across
# scanner instances never re-run filesystem checks. A cached None sticks (the
# tool may be installed later, but within one process run that's acceptable and
# far cheaper than stat()-ing every time).
_EXECUTABLE_CACHE: dict[str, Optional[str]] = {}


def _resolve_executable(name: str) -> Optional[str]:
    """Resolve an executable to an absolute path or None.

    Checks, in order:
      1. the system PATH (shutil.which),
      2. <sys.prefix>/bin (the active venv),
      3. common system bin directories (/usr/bin, /usr/local/bin,
         /usr/local/sbin, /opt/homebrew/bin),
      4. /snap/bin/ (Snap packages),
      5. ~/go/bin/ (Go tools).

    Only executable regular files are returned. The result is an absolute path
    that should be passed DIRECTLY to subprocess calls — never rely on shell
    PATH expansion at run time.
    """
    if not name:
        return None

    if name in _EXECUTABLE_CACHE:
        return _EXECUTABLE_CACHE[name]

    candidates: list[str] = []
    on_path = shutil.which(name)
    if on_path:
        candidates.append(on_path)
    candidates.append(os.path.join(sys.prefix, "bin", name))
    candidates.extend(os.path.join(search_dir, name) for search_dir in _SEARCH_PATHS)
    candidates.append(f"/snap/bin/{name}")
    candidates.append(os.path.expanduser(f"~/go/bin/{name}"))

    resolved = None
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            resolved = os.path.abspath(candidate)
            break

    _EXECUTABLE_CACHE[name] = resolved
    return resolved


class Scanner(ABC):
    """Base class for all scanners."""

    name: str = "base"
    executable: str = ""
    _resolved_path: Optional[str] = None  # cached absolute path

    @property
    def available(self) -> bool:
        """Whether this scanner's external dependency is installed and usable."""
        if not self.executable:
            return True
        self._resolved_path = _resolve_executable(self.executable)
        return self._resolved_path is not None

    @property
    def resolved_path(self) -> Optional[str]:
        """Absolute path to the resolved executable, or None."""
        if self._resolved_path is None:
            self._resolved_path = _resolve_executable(self.executable)
        return self._resolved_path

    @abstractmethod
    def scan(self, target: str, **kwargs) -> List[RawFinding]:
        """Scan a target and return raw findings. Must be implemented by subclasses."""


class ScanError(Exception):
    """Raised when a scanner fails to execute."""


# Registry of scanner classes (decorator registers the class; we instantiate
# on lookup so per-scan state is never shared across calls).
_SCANNERS: dict[str, type] = {}


def register(scanner_cls: type) -> type:
    """Register a scanner class by name. Returns the class unchanged so it
    can be used as a decorator."""
    _SCANNERS[scanner_cls.name] = scanner_cls
    return scanner_cls


def get_scanner(name: str) -> Scanner:
    """Instantiate a scanner by name."""
    if name not in _SCANNERS:
        raise KeyError(f"unknown scanner: {name}")
    return _SCANNERS[name]()


def available_scanners() -> list[str]:
    """Names of scanners whose external deps are installed."""
    return [name for name, cls in _SCANNERS.items() if cls().available]


def all_scanners() -> list[Scanner]:
    """Instantiate and return all registered scanners."""
    return [cls() for cls in _SCANNERS.values()]


def _run_scanner_checked(cls: type, target: str, **kwargs) -> List[RawFinding]:
    """Run a scanner, raising ScanError if its dependency is unavailable."""
    instance = cls()
    if not instance.available:
        raise ScanError(f"scanner '{instance.name}' unavailable: missing dependency "
                        f"'{instance.executable}'")
    return instance.scan(target, **kwargs)
