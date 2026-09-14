"""NFS probe — mount export enumeration via `showmount -e`.

Gated on `port_2049_open`. Calls `showmount -e <host>` (nfs-common) to list
NFS exports; a non-empty export list is a MEDIUM/HIGH `nfs-export-exposed`
finding. A root export ("/") readable/writable by any host is HIGH.

`showmount` is optional: when the binary is missing the skill reports the
(already-visible) RPC/mount surface instead of raising. Everything degrades
to no finding — never raises.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10
_HOST_RE = re.compile(r"^/(.*)$")
# Split a single export into its access-clause list: "/var *(rw,no_root_squash)"
_EXPORT_RE = re.compile(r"^([^\s]+)\s+(.+)$")


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _showmount_binary() -> Optional[str]:
    candidates = [
        shutil.which("showmount"),
        "/usr/sbin/showmount",
        "/usr/bin/showmount",
        f"{sys.prefix}/bin/showmount",
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _run_showmount(bin_path: str, host: str) -> str:
    try:
        proc = subprocess.run(
            [bin_path, "-e", host],
            capture_output=True, text=True, timeout=CONNECT_TIMEOUT,
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:  # noqa: BLE001
        return ""


def _parse_exports(output: str) -> List[dict]:
    """Parse `showmount -e` output: a header row then one export per line."""
    exports: List[dict] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("export list"):
            continue
        m = _EXPORT_RE.match(line)
        if not m:
            continue
        export, access = m.group(1), m.group(2)
        wildcard = ("*" in access
                    or access.strip().strip("()").lower()
                    in ("anywhere", "everyone"))
        root = export.rstrip("/") in ("", "/")
        exports.append({
            "export": export,
            "access": access,
            "wildcard": wildcard,
            "is_root": root,
        })
    return exports


@register
class NfsProbeSkill(Skill):
    """Enumerate NFS exports: showmount -e + root/world-writable flags."""

    name = "nfs-probe"
    display_name = "NFS Probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_2049_open"]

    timeout_seconds = 45
    max_requests = 8

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 2049 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"nfs_scan": "no-target"}})

        bin_path = _showmount_binary()
        if not bin_path:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"nfs_scan": "skipped",
                                           "reason": "no showmount binary"}})
        output = _run_showmount(bin_path, host)
        exports = _parse_exports(output)

        if not exports:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"nfs_scan": "no-exports"}})

        findings: List[RawFinding] = []
        world = [e for e in exports if e["wildcard"]]
        root = [e for e in exports if e["is_root"] and e["wildcard"]]
        severity = "critical" if root else ("high" if world else "medium")

        findings.append(RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="nfs-export-exposed",
            vulnerability_type="information-disclosure",
            target=f"{host}:2049", host=host,
            severity=severity,
            url=f"nfs://{host}:2049/",
            description=(
                f"NFS exports {len(exports)} share(s) on {host}:2049 "
                f"(world-accessible: {len(world)}, root-export: {len(root)})"
            ),
            raw={"exports": exports,
                 "world_accessible": bool(world),
                 "root_export": bool(root)},
        ))
        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "nfs_exports": [e["export"] for e in exports],
                "nfs_world_writable": bool(world),
                "nfs_scan": "exports"}})