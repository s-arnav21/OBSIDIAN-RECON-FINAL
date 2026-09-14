"""Certificate Transparency — crt.sh SAN enumeration and historical certificates.

Certificate Transparency logs public TLS certificates, so crt.sh lets us
enumerate every hostname a target's certificates have been issued for — a rich
source of subdomains, staging hostnames, and IP literals that never touches the
target itself.

From the crt.sh JSON response this skill:
  * aggregates the subjectAltName + common_name for every logged cert into a
    deduplicated, sorted subdomain list,
  * separates IP literals that leaked into SANs,
  * flags internal/hidden hostnames that should never appear in a public cert.

Findings:
  - INTERNAL_HOST_IN_CERT (MEDIUM) — internal/dev/staging hostname in a SAN
Context:
  - subdomains (SAN names, excluding wildcards and IPs)
Tools: nothing external (uses httpx against crt.sh)
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
MAX_SUBDOMAINS = 200

INTERNAL_HINTS = (
    "localhost", "dev", "staging", "test", "internal", "int-",
    ".local", ".internal", ".lan", ".corp", ".private",
)


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


def _is_internal(host: str) -> bool:
    low = host.lower()
    if low.startswith(INTERNAL_HINTS):
        return True
    if any(k in low for k in INTERNAL_HINTS):
        return True
    try:
        ip = socket.inet_aton(host.split("/")[0])
        first = (ip[0], ip[1], ip[2])
        if ip[0] == 10 or (ip[0] == 172 and 16 <= ip[1] <= 31) \
                or (ip[0] == 192 and ip[1] == 168) or ip[0] == 127:
            return True
    except OSError:
        pass
    return False


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _cert_names(domain: str) -> list[dict]:
    """Query crt.sh and return the raw list of cert dicts ([] on failure)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with _client() as c:
            r = c.get(url, timeout=TIMEOUT)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception:  # noqa: BLE001 - network / parse failure degrade quietly
        return []
    return data if isinstance(data, list) else []


def _parse_sans(certs: list[dict], domain: str) -> tuple[list[str], list[str]]:
    """Extract (subdomains, ip_sans) from crt.sh cert rows.

    Subdomains are SAN/common names under the target domain; wildcards and
    exact-domain matches are dropped. IP literals are returned separately.
    """
    names: set[str] = set()
    ips: set[str] = set()
    for row in certs:
        if not isinstance(row, dict):
            continue
        nv = row.get("name_value") or row.get("common_name") or ""
        for n in str(nv).split("\n"):
            n = n.strip().lower().rstrip(".")
            if not n or "*" in n:
                continue
            if _is_ip(n):
                ips.add(n)
                continue
            if n.endswith(f".{domain}") and n != domain:
                names.add(n)
    return sorted(names)[:MAX_SUBDOMAINS], sorted(ips)[:MAX_SUBDOMAINS]


@register
class CertTransparencySkill(Skill):
    """Query crt.sh for certificate-SAN subdomains and internal-host leaks."""

    name = "cert-transparency"
    display_name = "Certificate Transparency (SAN Enumeration)"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 60
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
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"crt_skipped": True}})

        certs = _cert_names(host)
        subdomains, ip_sans = _parse_sans(certs, host)

        osint_add["cert_sans"] = subdomains
        osint_add["cert_ip_sans"] = ip_sans

        # Only intercept subdomains that aren't already known.
        known = set(ctx.subdomains)
        new_subs = [s for s in subdomains if s not in known]

        for name in subdomains:
            if _is_internal(name):
                findings.append(self._internal_cert(host, name))
                break  # one finding is enough for this class

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint_add, "subdomains": new_subs})

    def _internal_cert(self, host: str, san: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="internal-host-in-cert",
            vulnerability_type="information-disclosure",
            target=host, host=host,
            severity="medium",
            description=(
                f"Internal/dev hostname leaked in certificate SAN of {host}: "
                f"{san} — reveals hidden infrastructure not meant for public DNS"
            ),
            raw={"host": host, "san_name": san},
        )

