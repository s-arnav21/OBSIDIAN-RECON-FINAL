"""BIND version disclosure probe — CHAOS TXT version.bind query.

Gated on `port_53_open`. Queries the target's BIND server via
`version.bind` CHAOS TXT (RFC 4892 / ISC recommendation to disable this).

A positive answer discloses the BIND version string and is flagged as a
MEDIUM `bind-version-disclosure` finding. This is the same leak visible
in the nmap banner ("ISC BIND 9.4.2") but confirmed directly against the
server's authoritative response.

Zone transfer: if version.bind returns a valid BIND version (9.x/8.x),
a one-shot AXFR attempt is made against the target for a synthetic zone
label (the target's reverse). This is a secondary best-effort check and
does not affect the finding if AXFR is refused.
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

_TIMEOUT = 8
_CHAOS_CLASS = 3  # CHAOS
_TXT_RRTYPE = 16  # TXT


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _query_version_bind(server: str) -> tuple[bool, str]:
    """Send `version.bind CHAOS TXT` and return (answered, version_string)."""
    try:
        import dns.message
        import dns.query
        import dns.name
        import dns.rdatatype
        import dns.rrset

        qname = dns.name.from_text("version.bind.")
        msg = dns.message.make_query(qname, dns.rdatatype.TXT,
                                     rdclass=_CHAOS_CLASS)
        resp = dns.query.udp(msg, server, timeout=_TIMEOUT)
        if resp.rcode() == 0 and resp.answer:
            rrset = resp.answer[0]
            for rdata in rrset:
                txt = rdata.to_text().strip('"').strip()
                if txt:
                    return True, txt
        return False, ""
    except Exception:  # noqa: BLE001
        return False, ""


def _try_axfr(server: str, domain: str) -> tuple[bool, list[str]]:
    """Best-effort zone transfer attempt (not critical for the finding)."""
    try:
        import dns.query
        import dns.zone

        xfr = dns.query.xfr(server, domain, timeout=_TIMEOUT, lifetime=_TIMEOUT + 4)
        zone = dns.zone.from_xfr(xfr)
        names = sorted(str(rname) for rname in zone.nodes)
        return True, names[:100]
    except Exception:  # noqa: BLE001
        return False, []


@register
class BindVersionProbeSkill(Skill):
    """Probe BIND version.bind CHAOS TXT and optional AXFR on port 53."""

    name = "bind-version-probe"
    display_name = "BIND version probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_53_open"]

    timeout_seconds = 30
    max_requests = 4

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 53 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"bind_version_scan": "no-target"}})

        try:
            import dns  # noqa: F401 — surface import errors
        except ImportError:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"bind_version_scan": "no-dnspython"}})

        answered, version = _query_version_bind(host)
        if not answered or not version:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {
                    "bind_version_scan": "no-answer",
                    "bind_version_disclosed": False}})

        # Best-effort zone transfer (informational, not critical to the finding)
        axfr_ok, axfr_names = _try_axfr(host, "version.bind.")
        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="bind-version-disclosure",
            vulnerability_type="information_disclosure",
            target=f"{host}:53", host=host,
            port=53,
            severity="medium",
            url=f"bind://{host}:53/",
            description=(
                f"BIND version disclosed via version.bind CHAOS TXT on {host}:53 — "
                f"{version[:60]}"
                + (f" (zone transfer: {len(axfr_names)} records)" if axfr_ok else "")
            ),
            raw={"version": version,
                 "server": host,
                 "axfr_successful": axfr_ok,
                 "axfr_record_count": len(axfr_names) if axfr_ok else 0},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {
                "bind_version": version,
                "bind_version_disclosed": True,
                "bind_version_scan": "disclosed"}})