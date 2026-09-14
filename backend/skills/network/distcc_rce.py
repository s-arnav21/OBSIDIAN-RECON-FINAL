"""DistCC RCE probe — detect the unauthenticated remote command execution
service (CVE-2004-2687) on distcc v1 (port 3632).

Gated on `port_3632_open`. Sends the benign `DISTCC_CMDLIST` request to
enumerate which commands the daemon will accept; a non-empty response proves
the service is accepting unauthenticated compilation requests. A benign
`id` command is run with a unique marker to confirm actual command execution
(CRITICAL); only a harmless echo is sent (no files are written).

`distcc-rce-signal` (HIGH) = version + CMDLIST accepted.
`distcc-rce-confirmed` (CRITICAL) = actual `echo .obsidian_probe_XXXX.` execution.
"""
from __future__ import annotations

import hashlib
import socket
import struct
from typing import List, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10
POKED_MARKER = ".obsidian_probe_" + hashlib.md5(b"distcc").hexdigest()[:8]


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _read_all(sock: socket.socket, limit: int = 65536, timeout: float = 8.0) -> bytes:
    buf = b""
    try:
        sock.settimeout(timeout)
        while len(buf) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        pass
    return buf


def _send_cmdlist_request(sock: socket.socket) -> bool:
    """Send DISTCC_CMDLIST and check if the server responds with a command.

    The CMDLIST request format (no arguments):
        header: [argc=1][argv_size=0]
        DARGV:   [cmd="DISTCC_CMDLIST"][len=1][data=DISTCC_CMDLIST]
    Returns True if the server replies with any command data (not an error).
    """
    try:
        sock.sendall(
            struct.pack("!II", 1, 0)
            + b"\x07CMDLIST"
        )
        resp = _read_all(sock, limit=8192, timeout=6)
        return bool(resp) and b"error" not in resp.lower()
    except Exception:  # noqa: BLE001
        return False


def _run_command(sock: socket.socket, cmd: str) -> Optional[str]:
    """Execute a command via the distcc protocol; returns stdout or None.

    Uses the same argc/argv protocol: argc=1, argv_size=0, DARGV for the
    command string. The server executes the command and sends its stdout
    as a raw stream that we capture up to our read limit.
    """
    try:
        payload = (
            struct.pack("!II", 1, 0)
            + cmd.encode("utf-8")
        )
        sock.sendall(payload)
        return _read_all(sock, limit=8192, timeout=8).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None


@register
class DistccRceProbeSkill(Skill):
    """Detect distccd remote command execution (CVE-2004-2687)."""

    name = "distcc-rce-probe"
    display_name = "DistCC RCE probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_3632_open"]

    timeout_seconds = 45
    max_requests = 6

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 3632 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"distcc_scan": "no-target"}})

        try:
            sock = socket.create_connection((host, 3632), timeout=CONNECT_TIMEOUT)
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"distcc_scan": "unreachable"}})

        try:
            cmdlist_ok = _send_cmdlist_request(sock)
            if not cmdlist_ok:
                return SkillResult(
                    skill_name=self.name, success=True, findings=[],
                    context_updates={"osint": {"distcc_scan": "no-cmdlist"}})

            marker_result = _run_command(sock, f"echo {POKED_MARKER}")
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"distcc_scan": "probe-error"}})
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

        rce_confirmed = bool(marker_result and POKED_MARKER in marker_result)
        severity = "critical" if rce_confirmed else "high"
        tid = "distcc-rce-confirmed" if rce_confirmed else "distcc-rce-signal"
        desc = (f"distccd v1 on {host}:3632 — "
                + ("remote command execution CONFIRMED (CVE-2004-2687, "
                   f"marker echoed: {marker_result.strip()[:40]})"
                   if rce_confirmed
                   else "unauthenticated CMDLIST accepted, RCE likely"))

        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id=tid,
            vulnerability_type="weak_credentials" if rce_confirmed else "information-disclosure",
            target=f"{host}:3632", host=host,
            port=3632,
            severity=severity,
            url=f"distcc://{host}:3632/",
            description=desc,
            raw={"rce_confirmed": rce_confirmed,
                 "cmdlist": True,
                 "marker": marker_result.strip()[:80] if marker_result else None},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {
                "distcc_rce_confirmed": rce_confirmed,
                "distcc_scan": "rce-confirmed" if rce_confirmed else "signal"}})