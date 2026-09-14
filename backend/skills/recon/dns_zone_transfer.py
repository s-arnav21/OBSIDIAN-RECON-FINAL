"""DNS Zone Transfer (AXFR) — attempt a zone transfer on all discovered nameservers.

A misconfigured nameserver that allows AXFR for an entire zone hands an attacker
a complete map of internal hostnames, subdomains, and IPs — effectively the
whole DNS surface in one query. This skill resolves the target's NS records and
tries an AXFR against each one, failing gracefully when the server refuses.

Trigger: always (the attempt is quick and refused transfers are silent).
Findings:
  - ZONE_TRANSFER_ENABLED (CRITICAL) with a sample of the dumped records
Tools: dnspython
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TIMEOUT_SECONDS = 8
LIFETIME_SECONDS = 20
MAX_RECORD_SAMPLE = 200


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


def _ns_for(domain: str) -> list[str]:
    """Resolve the NS records for a domain (or [] on any DNS failure)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "NS", lifetime=TIMEOUT_SECONDS)
        return [a.to_text().rstrip(".") for a in answers]
    except Exception:  # noqa: BLE001 - no NS records / resolution failure
        return []


def _ns_ip(nameserver: str) -> str | None:
    """Resolve a nameserver hostname to an IP (itself if already an IP)."""
    if _is_ip(nameserver):
        return nameserver
    try:
        return socket.gethostbyname(nameserver)
    except OSError:
        return None


def _try_axfr(nameserver_ip: str, domain: str) -> tuple[bool, list[str]]:
    """Attempt a zone transfer against a nameserver IP.

    Returns (success, sorted sample of zone record names). Any refusal,
    timeout, or protocol error simply yields success=False.
    """
    try:
        import dns.query
        import dns.zone
        xfr = dns.query.xfr(
            nameserver_ip, domain,
            timeout=TIMEOUT_SECONDS, lifetime=LIFETIME_SECONDS,
        )
        zone = dns.zone.from_xfr(xfr)
        names = sorted(str(rname) for rname in zone.nodes)
        return True, names[:MAX_RECORD_SAMPLE]
    except Exception:  # noqa: BLE001 - refused / not authoritative / timeout
        return False, []


@register
class DnsZoneTransferSkill(Skill):
    """Attempt a DNS zone transfer (AXFR) on all discovered nameservers."""

    name = "dns-zone-transfer"
    display_name = "DNS Zone Transfer"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 60
    max_requests = 16

    def should_run(self, ctx: SkillContext) -> bool:
        if not _extract_host(ctx):
            return False
        # Zone transfers only make sense for hostnames, not raw IPs.
        return not _is_ip(_extract_host(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)

        if not host or _is_ip(host):
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"zone_transfer_skipped": True}})

        import dns.resolver  # noqa: F401 - surface import errors loudly

        nameservers = _ns_for(host)
        if not nameservers:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"nameservers": []}})

        findings: list[RawFinding] = []
        last_zone: list[str] = []
        for ns in nameservers:
            ns_ip = _ns_ip(ns)
            if not ns_ip:
                continue
            ok, records = _try_axfr(ns_ip, host)
            if ok:
                last_zone = records
                findings.append(self._finding(host, ns, ns_ip, records))
                break  # one successful transfer is enough

        return SkillResult(
            skill_name=self.name,
            success=True,
            findings=findings,
            context_updates={"osint": {"nameservers": nameservers,
                                       "records": last_zone}},
        )

    def _finding(self, host: str, nameserver: str, ns_ip: str,
                 records: list[str]) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="zone-transfer-enabled",
            vulnerability_type="information-disclosure",
            target=host,
            host=host,
            severity="critical",
            description=(
                f"DNS zone transfer (AXFR) allowed by nameserver "
                f"{nameserver} ({ns_ip}) — full zone contents disclosed"
            ),
            raw={
                "nameserver": nameserver,
                "nameserver_ip": ns_ip,
                "zone": host,
                "record_count": len(records),
                "sample_records": records[:50],
            },
        )