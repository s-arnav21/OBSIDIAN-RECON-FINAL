"""Bindshell probe — detect a Metasploitable root bindshell (port 1524).

Gated on `port_1524_open`. Connects to the port and sends `id\n`; a response
containing `uid=` confirms command execution — typically root. This is the
classic Metasploitable 2 "Metasploitable root shell" bindshell, the single
highest-severity finding on the box.

`root-bindshell` (CRITICAL) = `id` output contains `uid=0`.
`bindshell` (HIGH) = port is a shell, but running as non-root user.
"""
from __future__ import annotations

import socket
from typing import Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10
_RESPONSE_TIMEOUT = 10


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _read_until_prompt(sock: socket.socket, limit: int = 4096) -> str:
    """Read until a shell prompt or EOF."""
    buf = b""
    try:
        sock.settimeout(_RESPONSE_TIMEOUT)
        while len(buf) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Stop early if we see a common prompt
            if buf.endswith(b"# ") or buf.endswith(b"$ "):
                break
    except (socket.timeout, OSError):
        pass
    return buf.decode("utf-8", errors="replace")


@register
class BindshellProbeSkill(Skill):
    """Detect a bindshell backdoor and confirm root access via `id`."""

    name = "bindshell-probe"
    display_name = "Bindshell probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_1524_open"]

    timeout_seconds = 30
    max_requests = 4

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 1524 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"bindshell_scan": "no-target"}})

        try:
            sock = socket.create_connection((host, 1524), timeout=CONNECT_TIMEOUT)
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"bindshell_scan": "unreachable"}})

        try:
            # Read the initial prompt/banner (Metasploitable prints "root@" etc.)
            banner = _read_until_prompt(sock, limit=8192)
            sock.sendall(b"id\n")
            id_output = _read_until_prompt(sock, limit=4096)
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"bindshell_scan": "read-error"}})
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

        full_output = banner + "\n" + id_output
        is_shell = bool(full_output.strip())
        is_root = "uid=0" in full_output.lower()

        if not is_shell:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"bindshell_scan": "no-response"}})

        severity = "critical" if is_root else "high"
        tid = "root-bindshell" if is_root else "bindshell"
        desc = (f"Bindable shell on {host}:1524 — "
                + (f"ROOT access confirmed (`id` returned: "
                   f"{id_output.strip()[:60]})"
                   if is_root
                   else f"non-root shell (`id` returned: {id_output.strip()[:60]})"))

        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id=tid,
            vulnerability_type="weak_credentials",
            target=f"{host}:1524", host=host,
            port=1524,
            severity=severity,
            url=f"bindshell://{host}:1524/",
            description=desc,
            raw={"id_output": id_output.strip()[:200],
                 "banner_excerpt": banner.strip()[:200],
                 "is_root": is_root, "is_shell": True},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {
                "bindshell_root": is_root,
                "bindshell_scan": "root" if is_root else "user"}})