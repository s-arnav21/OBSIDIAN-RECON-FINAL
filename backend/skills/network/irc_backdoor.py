"""UnrealIRCd backdoor check (CVE-2010-2075 / OSVDB-64582).

Gated on `port_6667_open` or `port_6697_open`. Connects, reads the IRC
banner, sends a minimal USER/NICK registration, then reads the 004 reply
to extract the server software and version. A version of `3.2.8.1` (the
only backdoored release) is flagged as HIGH. Older versions are flagged
as MEDIUM (exploitable pattern). Anything else is INFO.
"""
from __future__ import annotations

import socket
from typing import Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10
REG_TIMEOUT = 12


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _pick_port(ctx: SkillContext) -> int:
    for p in (6667, 6697):
        if p in ctx.open_ports:
            return p
    return 6667


def _read_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> str:
    buf = b""
    try:
        sock.settimeout(REG_TIMEOUT)
        while len(buf) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if marker in buf:
                break
    except (socket.timeout, OSError):
        pass
    return buf.decode("utf-8", errors="replace")


def _irc_004_version(banner_lines: str) -> Optional[str]:
    """Extract server version from the 004 reply:
    ``:<prefix> 004 <nick> <servername> <version> ...``"""
    for line in banner_lines.splitlines():
        parts = line.strip().split()
        if len(parts) >= 5 and parts[1] == "004":
            return parts[4]
    return None


def _parse_banner_version(banner_lines: str) -> Optional[str]:
    """Fallback: parse 'UnrealIRCd' or version from the raw banner."""
    for line in banner_lines.splitlines():
        low = line.lower()
        if "unrealircd" in low:
            tokens = line.split()
            for t in tokens:
                v = t.rstrip(".")
                if v and v[0].isdigit():
                    return v
        # Some servers include version in the 001 or NOTICE
        if "unrealircd" in low:
            return line.strip()
    return None


@register
class IrcBackdoorSkill(Skill):
    """Check for the UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075)."""

    name = "irc-backdoor"
    display_name = "UnrealIRCd backdoor check"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_6667_open", "port_6697_open"]

    timeout_seconds = 45
    max_requests = 4

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and any(
            p in ctx.open_ports for p in (6667, 6697))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        port = _pick_port(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"irc_scan": "no-target"}})

        sock: Optional[socket.socket] = None
        try:
            sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
            banner = _read_until(sock, b"\n", limit=16384)
            # Register minimally to receive 004
            sock.sendall(b"NICK reconbot\r\nUSER recon 0 * :recon\r\n")
            reply = _read_until(sock, b"004", limit=65536)
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"irc_scan": "unreachable"}})
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:  # noqa: BLE001
                    pass

        full = banner + "\n" + reply
        version = _irc_004_version(full) or _parse_banner_version(full)

        if not version:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"irc_scan": "no-version"}})

        vuln_version = "3.2.8.1" in version
        old_version = vuln_version or any(
            v in version for v in ("3.2.8", "3.2.7", "3.2.6", "3.1"))
        server_software = "UnrealIRCd" if "unrealircd" in full.lower() else version
        severity = "high" if vuln_version else ("medium" if old_version else "info")

        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="irc-backdoor-suspect" if vuln_version else "irc-version",
            vulnerability_type="weak_credentials" if vuln_version else "information_disclosure",
            target=f"{host}:{port}", host=host,
            port=port,
            severity=severity,
            url=f"irc://{host}:{port}/",
            description=(
                f"UnrealIRCd {version[:40]} detected on {host}:{port}"
                + (" — CVE-2010-2075 backdoor (3.2.8.1) SUSPECT"
                   if vuln_version else "")
            ),
            raw={"version": version, "software": server_software,
                 "vuln_version": vuln_version, "banner_excerpt": banner[:200]},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {
                "irc_version": version,
                "irc_software": server_software,
                "irc_backdoor_vuln": vuln_version,
                "irc_scan": "version-detected"}})