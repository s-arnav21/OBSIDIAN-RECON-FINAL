"""Reverse IP — co-hosted domains via HackerTarget.

The HackerTarget reverse-IP lookup maps a domain to the other domains sharing
its IP address. When a single IP hosts many unrelated domains it is a strong
signal of shared hosting — meaning the target shares infrastructure (and its
exposure/reputation) with neighbouring, attacker-influencible tenants.

This skill resolves the target hostname to an IP, queries the reverse-IP
service, and surfaces the neighbours.

Findings:
  - SHARED_HOSTING_DETECTED (INFO) — IP is shared by multiple domains
Context:
  - osint.neighbors (list of co-hosted domains)
Tools: nothing external (uses httpx against api.hackertarget.com)
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TIMEOUT = 10
USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")
# With at least this many co-hosted domains we call it shared hosting.
MIN_COHOSTED = 2
MAX_NEIGHBORS = 100


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


def _resolve_ip(host: str) -> str | None:
    """Resolve a hostname to an IPv4 address (None on failure)."""
    try:
        info = socket.getaddrinfo(host, None, socket.AF_INET)
        return info[0][4][0]
    except OSError:
        return None


def _parse_response(text: str) -> list[str]:
    """Parse a HackerTarget reverse-IP response into a host list ([] if error)."""
    if not text:
        return []
    if "error" in text.lower() or "api count exceeded" in text.lower():
        return []
    return [h.strip().lower().rstrip(".") for h in text.strip().splitlines()
            if h.strip()]


def _query_hosts(host: str) -> list[str]:
    """Query HackerTarget reverse-IP for a domain/fQDN; [] on failure."""
    url = f"https://api.hackertarget.com/reverseiplookup/?q={host}"
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True,
                          headers={"User-Agent": USER_AGENT}, verify=False) as c:
            text = c.get(url, timeout=TIMEOUT).text or ""
    except Exception:  # noqa: BLE001 - network failure degrades quietly
        return []
    return _parse_response(text)


@register
class ReverseIpSkill(Skill):
    """Enumerate co-hosted domains sharing the target's IP (shared hosting)."""

    name = "reverse-ip"
    display_name = "Reverse IP (Shared Hosting)"
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
        osint_add = {}

        if not host or _is_ip(host):
            return SkillResult(
                skill_name=self.name,
                success=True, findings=[],
                context_updates={"osint": {"reverse_ip_skipped": True}})

        ip = _resolve_ip(host)
        osint_add["resolved_ip"] = ip

        neighbors: list[str] = []
        if ip:
            neighbors = _query_hosts(host)[:MAX_NEIGHBORS]

        # Drop the target itself from the neighbour list.
        others = [n for n in neighbors if n != host]
        osint_add["neighbors"] = others

        if len(others) >= MIN_COHOSTED:
            findings.append(self._shared_hosting(host, ip, others))

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint_add})

    def _shared_hosting(self, host: str, ip: str | None,
                        others: list[str]) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="shared-hosting-detected",
            vulnerability_type="reputation",
            target=host, host=host,
            severity="info",
            description=(
                f"IP {ip or 'unknown'} for {host} hosts {len(others)} other "
                f"domains — shared hosting: neighbours share the target's "
                f"infrastructure and risk profile"
            ),
            raw={"host": host, "ip": ip, "neighbors": others[:20],
                 "neighbor_count": len(others)},
        )
