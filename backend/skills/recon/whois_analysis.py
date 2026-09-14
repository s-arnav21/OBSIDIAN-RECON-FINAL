"""WHOIS Analysis — expiry date, domain age, registrar, and privacy status.

Performing a WHOIS lookup against the domain's registration data reveals the
domain's lifecycle and how exposed its registration details are:

  * A domain that expires within days risks takeover/impersonation if the
    owner forgets to renew.
  * A freshly-registered domain is a common hallmark of phishing/malicious
    infrastructure.
  * A privacy/proxy registrar indicates the registrant hides behind a service.

The parser gracefully degrades when the underlying whois client is unavailable
or the registry returns nothing usable — no finding is emitted rather than a
hard failure.

Findings:
  - DOMAIN_EXPIRING_CRITICAL (HIGH)   — expiry within EXPIRY_DAYS_CRITICAL days
  - NEWLY_REGISTERED (MEDIUM)         — domain age below MIN_REGISTERED_DAYS
Tools: python-whois (bundled library, no external binary needed)
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TIMEOUT_SECONDS = 10
# Within this many days of expiry, flag as critical.
EXPIRY_DAYS_CRITICAL = 30
# Younger than this many days, flag as newly registered.
MIN_REGISTERED_DAYS = 180
# Registrar / org / reseller strings that indicate a privacy or proxy service.
PRIVACY_MARKERS = (
    "privacy", "proxy", "whoisprotect", "whois guardian",
    "withheld for privacy", "domains by proxy",
)

import whois  # noqa: E402 - heavy import kept together with helpers


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _first_dt(value) -> datetime | None:
    """Normalise a whois date field (single dt, list, or str) to a datetime."""
    if not value:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0]
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (ValueError, TypeError):
            return None
    return None


def _days_until(dt: datetime, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((dt - now).total_seconds() // 86400)


def _days_since(dt: datetime, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((now - dt).total_seconds() // 86400)


def _get_field(w, key: str):
    """Read a field from a python-whois result (dict-like or attribute-style)."""
    if isinstance(w, dict):
        return w.get(key)
    return getattr(w, key, None)


def _is_privacy(w) -> bool:
    """Detect WHOIS privacy/proxy registrations from registrar detail fields."""
    parts = [
        _get_field(w, "registrar"),
        _get_field(w, "reseller"),
        _get_field(w, "org"),
        _get_field(w, "registrant_org"),
        _get_field(w, "name"),
    ]
    haystack = " ".join(str(x) for x in parts if x).lower()
    return any(marker in haystack for marker in PRIVACY_MARKERS)


def _whois_lookup(host: str) -> dict | None:
    """Run the whois lookup; return the parsed dict, or None on failure."""
    try:
        return whois.whois(host, timeout=TIMEOUT_SECONDS) or None
    except Exception:  # noqa: BLE001 - client missing / registry unreachable
        return None


@register
class WhoisAnalysisSkill(Skill):
    """Analyse WHOIS data: expiry, age, registrar, and privacy status."""

    name = "whois-analysis"
    display_name = "WHOIS Analysis"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 30
    max_requests = 1

    def should_run(self, ctx: SkillContext) -> bool:
        if not _extract_host(ctx):
            return False
        return not _is_ip(_extract_host(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        findings: list[RawFinding] = []
        osint = {}

        if not host or _is_ip(host):
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"whois_skipped": True}})

        data = _whois_lookup(host)
        if data is None:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"whois": None}})

        w = data
        registrar = w.get("registrar") or ""
        creation = _first_dt(w.get("creation_date"))
        expiry = _first_dt(w.get("expiration_date"))
        privacy = _is_privacy(w)

        osint["whois"] = {
            "registrar": registrar,
            "creation_date": creation.isoformat() if creation else None,
            "expiration_date": expiry.isoformat() if expiry else None,
            "privacy": privacy,
            "name_servers": _get_field(w, "name_servers") or [],
        }

        if expiry is not None and _days_until(expiry) <= EXPIRY_DAYS_CRITICAL:
            findings.append(self._expiring(host, registrar, expiry))
        if creation is not None and _days_since(creation) < MIN_REGISTERED_DAYS:
            findings.append(self._newly_registered(host, creation))

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint})

    def _expiring(self, host: str, registrar: str,
                  expiry: datetime) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="domain-expiring-critical",
            vulnerability_type="availability",
            target=host, host=host,
            severity="high",
            description=(
                f"Domain {host} expires within {EXPIRY_DAYS_CRITICAL} days "
                f"({expiry.isoformat()}) — risk of lapse, takeover, or "
                f"impersonation if registration is not renewed"
            ),
            raw={"host": host, "registrar": registrar,
                 "expiration_date": expiry.isoformat(),
                 "days_until_expiry": _days_until(expiry)},
        )

    def _newly_registered(self, host: str, creation: datetime) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="newly-registered",
            vulnerability_type="reputation",
            target=host, host=host,
            severity="medium",
            description=(
                f"Domain {host} was only recently registered "
                f"({creation.isoformat()}, {_days_since(creation)} days ago) "
                f"— frequent hallmark of phishing or malicious infrastructure"
            ),
            raw={"host": host, "creation_date": creation.isoformat(),
                 "days_registered": _days_since(creation)},
        )
