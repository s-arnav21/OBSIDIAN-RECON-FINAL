"""Core contract for Obsidian Recon MITRE technique automation scripts.

An *automation script* (``TechniqueScript``) is a self-contained, deterministic,
bounded unit of work that implements exactly one MITRE ATT&CK technique against
an authorized target. The LLM planner (or the deterministic kill-chain runner)
selects a script by its ``technique_id``; the script declares the capabilities
it needs (``requires_any``) and the capabilities it grants on success
(``provides``) so it plugs straight into the existing capability graph
(``app.attack_chain.engine`` / ``app.services.privilege_escalation``).

Design rules every script must obey:

  * **Bounded** — every external call carries a timeout and an output cap.
  * **Deterministic** — the payloads are fixed; the LLM chooses *where* and
    *whether*, never *how*.
  * **Evidence-first** — result carries structured, size-capped evidence.
  * **Fail-soft** — a script never raises to the caller; it returns an
    ``error``/``blocked`` result so one failed technique cannot abort a chain.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from app.models.finding import Finding

# ---------------------------------------------------------------------------
# Status vocabulary
# ---------------------------------------------------------------------------


class TechniqueStatus:
    """Terminal outcome of one technique execution."""

    CONFIRMED = "confirmed"        # technique succeeded and granted capabilities
    REJECTED = "rejected"          # technique ran and negatively confirmed
    INCONCLUSIVE = "inconclusive"  # ran but neither confirmed nor denied
    ERROR = "error"                # a bounded execution error occurred
    BLOCKED = "blocked"            # policy/config prevented execution
    SKIPPED = "skipped"            # not applicable or prerequisite missing

    SUPPORTED = frozenset({
        CONFIRMED,
        REJECTED,
        INCONCLUSIVE,
        ERROR,
        BLOCKED,
        SKIPPED,
    })

    #: Statuses that mean "the technique produced a usable signal".
    EFFECTIVE = frozenset({CONFIRMED, REJECTED})


# ---------------------------------------------------------------------------
# Execution context and result
# ---------------------------------------------------------------------------

_MAX_SUMMARY = 512
_MAX_EVIDENCE_ITEMS = 48
_MAX_ARTIFACTS = 32


def _bounded(value: Any, maximum: int) -> str:
    text = "" if value is None else str(value)
    text = text.strip()
    if len(text) <= maximum:
        return text
    return text[: maximum - 1] + "\u2026"


def _bounded_mapping(values: Any, *, max_items: int) -> Dict[str, Any]:
    """Coerce a mapping into bounded, JSON-safe scalars/lists."""
    if not isinstance(values, dict):
        return {}
    result: Dict[str, Any] = {}
    for key, value in list(values.items())[:max_items]:
        if not isinstance(key, str) or not key.strip():
            continue
        safe_key = _bounded(key, 128)
        if isinstance(value, (str, int, float, bool)) or value is None:
            if isinstance(value, str):
                result[safe_key] = _bounded(value, 2000)
            else:
                result[safe_key] = value
        elif isinstance(value, (list, tuple)):
            result[safe_key] = [
                _bounded(item, 512)
                for item in list(value)[:32]
                if isinstance(item, (str, int, float, bool))
            ]
        elif isinstance(value, dict):
            result[safe_key] = {
                _bounded(k, 128): _bounded(v, 512)
                for k, v in list(value.items())[:32]
                if isinstance(k, str) and isinstance(v, (str, int, float, bool))
            }
    return result


@dataclass
class AutomationContext:
    """Everything one technique script needs to act.

    The context is assembled by the runner from the trusted agent state plus the
    caller-supplied HTTP/DB sessions. It never carries raw secret material; the
    scripts that need credentials read them from bounded findings.
    """

    target: str                                  # canonical authorized origin
    authorized: bool = False
    finding: Optional[Finding] = None
    options: Dict[str, str] = field(default_factory=dict)
    capabilities: Tuple[str, ...] = field(default_factory=tuple)
    http_session: Any = None
    db_session: Any = None
    artifact_dir: Optional[str] = None
    timeout_seconds: int = 120
    lhost: str = "127.0.0.1"
    lport: int = 4444
    allow_remote_fetch: bool = False
    #: A ready authenticated *target* session (see ``app.automation.session``).
    #: When present, techniques that need to run something on the target use it
    #: instead of the HTTP command-execution path. Attributed to every result so
    #: a claim of execution/discovery always names the target it ran against.
    session: Any = None
    #: Bounded credential material recovered earlier (e.g. by T1078). Secrets
    #: are never logged; they exist so a later technique can *validate* them by
    #: opening a real session rather than trusting the recovery step alone.
    credentials: Dict[str, str] = field(default_factory=dict)

    def has_capability(self, *names: str) -> bool:
        return any(name in self.capabilities for name in names)

    def merged_options(self) -> Dict[str, Any]:
        """Technique-native options merged from finding context + overrides."""
        opts: Dict[str, Any] = dict(self.options)
        finding = self.finding
        if finding is not None:
            opts.setdefault("endpoint", finding.endpoint or finding.target)
            opts.setdefault("http_method", finding.http_method or "GET")
            if finding.parameter_name:
                opts.setdefault("parameter_name", finding.parameter_name)
            if finding.parameter_location:
                opts.setdefault("parameter_location", finding.parameter_location)
            opts.setdefault("vulnerability_type", finding.vulnerability_type)
            opts.setdefault("validator_id", finding.validator_id or "")
        return opts


@dataclass
class TechniqueResult:
    """Structured outcome of a technique script."""

    technique_id: str
    status: str
    summary: str
    provides: Tuple[str, ...] = field(default_factory=tuple)
    evidence: Dict[str, Any] = field(default_factory=dict)
    artifacts: Tuple[str, ...] = field(default_factory=tuple)
    next_techniques: Tuple[str, ...] = field(default_factory=tuple)
    duration_ms: int = 0
    error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in TechniqueStatus.SUPPORTED:
            raise ValueError(f"unsupported technique status {self.status!r}")
        self.technique_id = str(self.technique_id)
        self.summary = _bounded(self.summary, _MAX_SUMMARY) or "no summary"
        self.provides = tuple(dict.fromkeys(
            str(cap) for cap in self.provides if str(cap).strip()
        ))
        self.evidence = _bounded_mapping(
            self.evidence, max_items=_MAX_EVIDENCE_ITEMS
        )
        self.artifacts = tuple(
            _bounded(path, 1024) for path in list(self.artifacts)[:_MAX_ARTIFACTS]
        )
        self.next_techniques = tuple(dict.fromkeys(
            str(t) for t in self.next_techniques if str(t).strip()
        ))
        if self.error is not None:
            self.error = _bounded(self.error, _MAX_SUMMARY)

    @property
    def confirmed(self) -> bool:
        return self.status == TechniqueStatus.CONFIRMED

    @property
    def capabilities_gained(self) -> Tuple[str, ...]:
        """Capabilities actually granted (only on confirmation)."""
        return self.provides if self.confirmed else ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "status": self.status,
            "summary": self.summary,
            "provides": list(self.provides),
            "capabilities_gained": list(self.capabilities_gained),
            "evidence": self.evidence,
            "artifacts": list(self.artifacts),
            "next_techniques": list(self.next_techniques),
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Technique script base class
# ---------------------------------------------------------------------------


class TechniqueScript(ABC):
    """Base class every MITRE technique automation script implements."""

    # --- Identity (must be set by subclasses) ---
    technique_id: str = ""
    name: str = ""
    tactic: str = ""
    description: str = ""

    # --- Capability graph wiring ---
    requires_any: Tuple[str, ...] = ()
    requires_all: Tuple[str, ...] = ()
    provides: Tuple[str, ...] = ()

    # --- Applicability ---
    vuln_types: Tuple[str, ...] = ()
    allowed_options: Tuple[str, ...] = ()

    #: When False the LLM may not auto-select this script; an operator must
    #: explicitly opt in (e.g. destructive post-exploitation). The policy gate
    #: enforces this flag.
    automatic_allowed: bool = True

    def applicable(self, ctx: AutomationContext) -> bool:
        """Return True when the technique's prerequisites are satisfied."""
        if self.requires_all and not all(
            req in ctx.capabilities for req in self.requires_all
        ):
            return False
        if self.requires_any and not any(
            req in ctx.capabilities for req in self.requires_any
        ):
            return False
        return True

    @abstractmethod
    def execute(self, ctx: AutomationContext) -> TechniqueResult:
        """Run the technique. Must never raise; return an error result instead."""
        raise NotImplementedError

    def describe(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "requires_all": list(self.requires_all),
            "requires_any": list(self.requires_any),
            "provides": list(self.provides),
            "vuln_types": list(self.vuln_types),
            "allowed_options": list(self.allowed_options),
            "automatic_allowed": self.automatic_allowed,
        }


__all__ = [
    "TechniqueStatus",
    "TechniqueResult",
    "TechniqueScript",
    "AutomationContext",
]
