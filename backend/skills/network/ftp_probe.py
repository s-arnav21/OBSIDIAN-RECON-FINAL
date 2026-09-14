"""FTP probe — anonymous login, directory listing, sensitive files.

Gated on `port_21_open`. Connects to the FTP service with ftplib, captures the
banner, then tries the standard anonymous credential pairs (`anonymous`,
`ftp`). A successful anonymous login is a HIGH `ftp-anonymous-login` finding;
the root listing is examined for sensitive filenames (passwd, shadow, config,
database dumps, backups) which raise a MEDIUM `ftp-sensitive-file` finding.

Self-contained (stdlib `ftplib`, no external tools); every failure degrades
to no finding.
"""
from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlparse

import ftplib

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 12

_ANON_USERS = ("anonymous", "ftp")

# ProFTPD 1.3.3c ships a hardcoded backdoor (CVE-2010-4221): TCP 6200/6201
# shell via a format-string bug in the %f bar motif. The mere banner — not just
# a successful login — identifies the vulnerable build.
_BACKDOOR_RE = re.compile(r"proftpd[\s/]*1\.3\.3c\b", re.I)

_SENSITIVE_RE = re.compile(
    r"(passwd|shadow|\.htpasswd|htpasswd|config(\.|_)|db\.|\.sql|\.db|"
    r"backup|bak|\.tar|\.gz|\.zip|\.env|credential|secret|key|dump)", re.I)


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _port(ctx: SkillContext) -> int:
    if 21 in ctx.open_ports:
        return 21
    return ctx.port or 21


@register
class FtpProbeSkill(Skill):
    """Probe FTP: anonymous login + listing + sensitive files."""

    name = "ftp-probe"
    display_name = "FTP Probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_21_open"]

    timeout_seconds = 45
    max_requests = 12

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 21 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"ftp_scan": "no-target"}})
        port = _port(ctx)

        ftp: Optional[ftplib.FTP] = None
        banner = ""
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=CONNECT_TIMEOUT)
            banner = ftp.getwelcome() or ""
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"ftp_scan": "unreachable",
                                           "ftp_banner": banner}})

        findings: list[RawFinding] = []
        if _BACKDOOR_RE.search(banner):
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="ftp-backdoor",
                vulnerability_type="remote_code_execution",
                target=f"{host}:{port}", host=host,
                severity="high",
                url=f"ftp://{host}:{port}/",
                description=(
                    f"ProFTPD 1.3.3c on {host}:{port} runs the CVE-2010-4221 "
                    f"backdoored build — an unauthenticated connection spawns "
                    f"a root shell on TCP 6200/6201"),
                raw={"banner": banner,
                     "cve": "CVE-2010-4221",
                     "backdoor_ports": [6200, 6201]},
            ))

        anonymous_ok = False
        try:
            ok = ftp.login(_ANON_USERS[0], _ANON_USERS[0] + "@example.com")
            anonymous_ok = str(ok).startswith("2")
        except ftplib.error_perm:
            anonymous_ok = False
        except Exception:  # noqa: BLE001
            pass
        if not anonymous_ok:
            try:
                ftp.login("ftp", "ftp")
                anonymous_ok = True
            except Exception:  # noqa: BLE001
                anonymous_ok = False

        listing: list[str] = []
        if anonymous_ok:
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="ftp-anonymous-login",
                vulnerability_type="weak_credentials",
                target=f"{host}:{port}", host=host,
                severity="high",
                url=f"ftp://{host}:{port}/",
                description=(
                    f"FTP allows anonymous login on {host}:{port} "
                    f"(banner: {banner[:60]!r})"),
                raw={"banner": banner,
                     "credentials": ("anonymous", "any"),
                     "listing_enabled": bool(ftp.nlst())},
            ))
            try:
                raw_list = ftp.nlst() or []
                listing = [str(f) for f in raw_list]
            except Exception:  # noqa: BLE001
                listing = []
            sensitive = [f for f in listing if _SENSITIVE_RE.search(f)]
            if sensitive:
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="ftp-sensitive-file",
                    vulnerability_type="information_disclosure",
                    target=f"{host}:{port}", host=host,
                    severity="medium",
                    url=f"ftp://{host}:{port}/",
                    description=(
                        f"sensitive filenames readable via anonymous FTP: "
                        f"{', '.join(sensitive[:8])}"),
                    raw={"sensitive_files": sensitive[:16],
                         "listing": listing[:50]},
                ))
        try:
            ftp.quit()
        except Exception:  # noqa: BLE001
            pass

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {
                    "ftp_scan": "auth-required", "ftp_banner": banner}})

        osint: dict = {
            "ftp_banner": banner,
            "ftp_scan": "anonymous" if "ftp-anonymous-login" in
                        {f.scanner_template_id for f in findings}
                        else "backdoor",
        }
        if anonymous_ok:
            osint.update({"ftp_anonymous": True,
                          "ftp_listing": listing[:50]})
        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint})