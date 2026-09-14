"""Email Security Checks — SPF, DMARC, and DKIM record validation.

Email spoofing protection relies on three DNS-based mechanisms that publish
sender policy:

  * SPF  (TXT record)      — which hosts may send mail for the domain.
  * DMARC (TXT _dmarc)     — what receivers should do with failing mail, and
                             where to send forensic reports.
  * DKIM (TXT selector._domainkey) — signature verification public keys.

A missing/permissive SPF, a `~all`/`?all` catch-all, or a DMARC `p=none`
policy all leave the domain open to spoofing and phishing impersonation.

Findings:
  - SPF_MISSING      (MEDIUM) — no SPF record published at all
  - SPF_PERMISSIVE   (HIGH)   — SPF exists but uses `~all`/`?all` (soft fail)
  - DMARC_POLICY_NONE (LOW)   — DMARC record present with `p=none`
Tools: dnspython
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TIMEOUT_SECONDS = 8


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


def _txt_record(domain: str) -> str:
    """Return the raw SPF TXT value for a domain ('' if none/failure)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "TXT", lifetime=TIMEOUT_SECONDS)
        for ans in answers:
            text = "".join(s.decode() if isinstance(s, bytes) else s
                           for s in ans.strings)
            if "v=spf1" in text.lower():
                return text
        return ""
    except Exception:  # noqa: BLE001 - no TXT / NXDOMAIN / resolution failure
        return ""


def _dmarc_record(host: str) -> str:
    """Return the DMARC TXT value for a host ('' if none/failure)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(f"_dmarc.{host}", "TXT",
                                       lifetime=TIMEOUT_SECONDS)
        for ans in answers:
            text = "".join(s.decode() if isinstance(s, bytes) else s
                           for s in ans.strings)
            if text.lower().startswith("v=dmarc1"):
                return text
        return ""
    except Exception:  # noqa: BLE001 - no DMARC / NXDOMAIN / resolution failure
        return ""


def _dkim_signers(host: str) -> list[str]:
    """Return the selectors that carry a valid DKIM public key for host.

    A curated default set of common selectors is tried; each selector that
    resolves to a TXT record containing a DKIM public key (
    `v=dkim1; p=...`) is considered an active signer.
    """
    import dns.resolver
    selectors = [
        "default", "google", "selector1", "selector2", "k1", "s1",
        "s2016", "20160601", "dkim", "mail", "smtp",
    ]
    signers: list[str] = []
    for sel in selectors:
        try:
            answers = dns.resolver.resolve(
                f"{sel}._domainkey.{host}", "TXT",
                lifetime=min(TIMEOUT_SECONDS, 3))
            found = False
            for ans in answers:
                text = "".join(s.decode() if isinstance(s, bytes) else s
                               for s in ans.strings)
                if text.lower().startswith("v=dkim1"):
                    found = True
                    break
            if found:
                signers.append(sel)
        except Exception:  # noqa: BLE001 - selector absent
            continue
    # If every selector failed with NXDOMAIN-style errors, DNS is likely
    # silently failing; treat as no DKIM published (signers stays empty).
    return signers


def _spf_quality(spf: str) -> str:
    """Classify an SPF record: 'missing', 'permissive', or 'ok'."""
    if not spf:
        return "missing"
    term = spf.strip().rsplit(" ", 1)[-1]
    # Soft-fail / neutral mechanisms leave spoofing possible
    if "~all" in spf or "?all" in spf:
        return "permissive"
    return "ok"


@register
class EmailSecuritySkill(Skill):
    """Check SPF, DMARC, and DKIM email-authentication records."""

    name = "email-security"
    display_name = "Email Security (SPF/DMARC/DKIM)"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 60
    max_requests = 24

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
                context_updates={"osint": {"email_security_skipped": True}})

        spf = _txt_record(host)
        dmarc = _dmarc_record(host)
        dkim_signers = _dkim_signers(host)

        osint["spf"] = spf
        osint["dmarc"] = dmarc
        osint["dkim_selectors"] = dkim_signers

        quality = _spf_quality(spf)
        if quality == "missing":
            findings.append(self._spf_missing(host))
        elif quality == "permissive":
            findings.append(self._spf_permissive(host, spf))

        if dmarc and "p=none" in dmarc.replace(" ", "").lower():
            findings.append(self._dmarc_none(host, dmarc))

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint})

    def _spf_missing(self, host: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="spf-missing",
            vulnerability_type="spoofing",
            target=host, host=host,
            severity="medium",
            description=(
                f"No SPF record found for {host} — the domain publishes no "
                f"sender policy and is trivially spoofable for phishing"
            ),
            raw={"host": host, "spf": ""},
        )

    def _spf_permissive(self, host: str, spf: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="spf-permissive",
            vulnerability_type="spoofing",
            target=host, host=host,
            severity="high",
            description=(
                f"SPF record for {host} uses a soft-fail/neutral catch-all "
                f"(~all / ?all), so spoofed mail may still pass receivers"
            ),
            raw={"host": host, "spf": spf},
        )

    def _dmarc_none(self, host: str, dmarc: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="dmarc-policy-none",
            vulnerability_type="spoofing",
            target=host, host=host,
            severity="low",
            description=(
                f"DMARC policy for {host} is 'none' (p=none) — receivers only "
                f"monitor and do not reject spoofed mail"
            ),
            raw={"host": host, "dmarc": dmarc},
        )
