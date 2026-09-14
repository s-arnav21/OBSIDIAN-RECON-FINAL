"""TLS Audit — nmap crypto-policy checks: Heartbleed, POODLE, weak protocols.

Runs nmap's bundled TLS scripts against every TLS port that phase-scans found
(plus the primary target port), without any extra installs:

    nmap -sV --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed <host>

From the script output it derives three finding classes:

  * TLS_WEAK_PROTOCOL (HIGH)  — obsolete protocol offered (SSLv2, SSLv3,
                                TLSv1.0, TLSv1.1). SSLv3 also implies POODLE.
  * HEARTBLEED        (CRITICAL) — OpenSSL CVE-2014-0160 vulnerable.
  * (supporting) weak cipher suites configured (RC4/3DES/DES).

Only runs when a TLS port was already observed open (port_443_open /
port_8443_open), so it never probes arbitrary closed ports.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import os
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TLS_PORT_HINTS = (443, 8443, 9443, 4280, 8443, 10443, 8447, 9443)
_OLD_PROTOCOLS = ("sslv2", "sslv3", "tlsv1.0", "tlsv1.1")
_PROTOCOL_NAMES = {"sslv2": "SSLv2", "sslv3": "SSLv3",
                   "tlsv1.0": "TLSv1.0", "tlsv1.1": "TLSv1.1"}
_WEAK_CIPHER_MARKERS = ("rc4", "des", "3des")
TIMEOUT = 120


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _nmap_binary() -> str | None:
    candidates = [shutil.which("nmap"), "/usr/bin/nmap",
                  "/usr/local/bin/nmap", f"{sys.prefix}/bin/nmap"]
    for c in candidates:
        if c and c.strip() and os.path.isfile(c):
            return c
    return None


def _tls_ports(ctx: SkillContext) -> list[int]:
    """Ports to audit: known-open TLS hints first, then the target port."""
    hints = [p for p in ctx.open_ports if p in TLS_PORT_HINTS]
    if ctx.port and ctx.port not in hints:
        hints.append(int(ctx.port))
    if hints:
        return sorted(set(hints))
    return [443]  # blind fallback — never the common case


def _build_command(nmap_bin: str, host: str, ports: list[int]) -> list[str]:
    return [nmap_bin, "-T4", "--host-timeout", f"{TIMEOUT}s",
            "-p", ",".join(str(p) for p in ports), "-sV",
            "--script", "ssl-cert,ssl-enum-ciphers,ssl-heartbleed", host]


def _run_nmap(cmd: list[str], timeout: int = TIMEOUT) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:  # noqa: BLE001 - binary/timeout/OSError degrade quietly
        return ""


def _split_script_output(output: str) -> dict[int, str]:
    """Group nmap script output lines by port number."""
    port: int | None = None
    sections: dict[int, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if "open" in stripped and "/tcp" in stripped:
            try:
                port = int(stripped.split("/tcp")[0])
                sections.setdefault(port, "")
            except ValueError:
                port = None
            continue
        if port is not None and stripped.startswith("|"):
            sections[port] += stripped + "\n"
    return sections


def _subsection(text: str, name: str) -> str:
    sections: dict[str, str] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("| _"):
            current = None
            continue
        if line.startswith("|"):
            rest = line.lstrip("| ")
            for key in ("ssl-cert", "ssl-enum-ciphers", "ssl-heartbleed"):
                if rest.startswith(key + ":"):
                    current = key
                    sections.setdefault(current, "")
                    sections[current] += rest.split(":", 1)[1] + "\n"
                    break
            else:
                if current:
                    sections[current] += line.lstrip("| ") + "\n"
    return sections.get(name, "")


def _weak_protocols(text: str) -> list[str]:
    """Return offered obsolete protocols in report form (e.g. ['TLSv1.0'])."""
    section = _subsection(text, "ssl-enum-ciphers")
    present: set[str] = set()
    for raw in section.splitlines():
        low = raw.strip().rstrip(":").lower()
        for proto in _OLD_PROTOCOLS:
            if low == proto:
                present.add(_PROTOCOL_NAMES[proto])
    return sorted(present)


def _weak_ciphers(text: str) -> list[str]:
    section = _subsection(text, "ssl-enum-ciphers").lower()
    return [m for m in _WEAK_CIPHER_MARKERS if m in section]


def _heartbleed_vulnerable(text: str) -> bool:
    hb = _subsection(text, "ssl-heartbleed").lower()
    if "not vulnerable" in hb:
        return False
    return "vulnerable" in hb


@register
class TlsAuditSkill(Skill):
    """Audit TLS policy: Heartbleed, POODLE, weak protocols/ciphers."""

    name = "tls-audit"
    display_name = "TLS Audit"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = ["port_443_open", "port_8443_open"]
    requires_tools: list[str] = ["nmap"]

    timeout_seconds = 130
    max_requests = 1

    def should_run(self, ctx: SkillContext) -> bool:
        if not _extract_host(ctx):
            return False
        return any(p in ctx.open_ports for p in (443, 8443))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        findings: list[RawFinding] = []

        if not host or not any(p in ctx.open_ports for p in (443, 8443)):
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"tls_skipped": True}})

        nmap_bin = _nmap_binary()
        if not nmap_bin:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                error="nmap binary not found",
                context_updates={"osint": {"tls_skipped": True,
                                           "reason": "no nmap binary"}})

        ports = _tls_ports(ctx)
        output = _run_nmap(_build_command(nmap_bin, host, ports))

        sections = _split_script_output(output)
        ports_audited = sorted(sections.keys())
        osint_add = {"tls_ports": ports_audited or ports}

        for port, text in sections.items():
            if not text:
                continue
            weak = _weak_protocols(text)
            for proto in weak:
                severity = "critical" if proto == "SSLv2" else "high"
                desc = f"obsolete TLS/SSL protocol offered on port {port}: {proto}"
                if proto == "SSLv3":
                    desc += " (POODLE CVE-2014-3566 applies)"
                findings.append(self._protocol_finding(
                    host, port, proto, severity, desc))
                if proto == "SSLv3":
                    findings.append(self._poodle_finding(host, port))

            for marker in _weak_ciphers(text):
                findings.append(self._weak_cipher_finding(host, port, marker))

            if _heartbleed_vulnerable(text):
                findings.append(self._heartbleed_finding(host, port))
                osint_add["heartbleed_ports"] = (
                    osint_add.get("heartbleed_ports", []) + [port])

        osint_add["tls_weak_protocols"] = sorted(set(
            proto for s in sections.values() for proto in _weak_protocols(s)))
        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint_add})

    def _protocol_finding(self, host: str, port: int, proto: str,
                          severity: str, description: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="tls-weak-protocol",
            vulnerability_type="crypto",
            target=host, host=host, port=port, service="ssl",
            severity=severity,
            description=description,
            raw={"host": host, "port": port, "protocol": proto},
        )

    def _poodle_finding(self, host: str, port: int) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="poodle-ssl3",
            vulnerability_type="crypto",
            target=host, host=host, port=port, service="ssl",
            severity="high",
            description=(
                f"SSLv3 padding-oracle (POODLE, CVE-2014-3566) applicable "
                f"on port {port} — SSLv3 must be disabled"
            ),
            raw={"host": host, "port": port, "cve": "CVE-2014-3566"},
        )

    def _weak_cipher_finding(self, host: str, port: int,
                             marker: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="tls-weak-cipher",
            vulnerability_type="crypto",
            target=host, host=host, port=port, service="ssl",
            severity="low",
            description=(
                f"weak cipher suite marker '{marker}' offered on port {port}"
            ),
            raw={"host": host, "port": port, "marker": marker},
        )

    def _heartbleed_finding(self, host: str, port: int) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="heartbleed",
            vulnerability_type="crypto",
            target=host, host=host, port=port, service="ssl",
            severity="critical",
            description=(
                f"OpenSSL Heartbleed (CVE-2014-0160) vulnerable on port {port}"
            ),
            raw={"host": host, "port": port, "cve": "CVE-2014-0160"},
        )