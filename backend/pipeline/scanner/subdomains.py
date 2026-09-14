"""Passive subdomain discovery — subfinder + dnsx.

subfinder discovers subdomains from passive OSINT sources (no direct scanning
of the target), and dnsx resolves which of those subdomains are actually live.
Each live subdomain becomes an `info` finding so the operator can see the
attack surface; these are candidates for later, deeper TTP-driven scanning.

Boundary: the scanner never actively probes each subdomain — it only resolves
them. If a subdomain count exceeds MAX_SUBDOMAIN_FINDINGS, the rest are kept in
`self.detail` (not dropped) but not emitted as individual findings.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from pipeline.scanner import base

MAX_SUBDOMAIN_FINDINGS = 200

LOCAL_BIN = Path.home() / ".local" / "bin"


def resolve_executable(name: str) -> Optional[str]:
    """Resolve a tool: honour PATH, then fall back to ~/.local/bin,
    venv/bin, and common system bin directories.

    The console server may not be launched with these paths on PATH, so
    scanners must find installed tools explicitly rather than relying on
    shutil.which alone.
    """
    import os
    import shutil

    on_path = shutil.which(name)
    if on_path:
        return str(on_path)
    local = LOCAL_BIN / name
    if local.exists() and os.access(local, os.X_OK):
        return str(local)
    # Delegate to the shared resolver (venv/bin, /usr/bin, /usr/local/bin).
    from pipeline.scanner.base import _resolve_executable
    return _resolve_executable(name)


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.hostname or target.strip()
    host = host.strip("[]")  # IPv6 brackets
    # strip port if it snuck through with a bare host:port
    host = host.split(":")[0]
    return host


def _is_ip(host: str) -> bool:
    import socket

    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


@base.register
class SubdomainScanner(base.Scanner):
    name = "subdomains"
    executable = "subfinder"

    def __init__(self) -> None:
        self.warning: Optional[str] = None
        self.detail: Optional[dict] = None
        self._bin: Optional[str] = None

    @property
    def available(self) -> bool:
        return all(resolve_executable(e) for e in ("subfinder", "dnsx"))

    def scan(self, target: str, timeout: int = 120) -> List[RawFinding]:
        self.warning = None
        self.detail = None
        domain = _extract_domain(target)
        if _is_ip(domain):
            self.warning = "target is an IP address; subdomain discovery skipped"
            self.detail = {"domain": domain, "mode": "skipped-ip"}
            return []

        subfinder_bin = resolve_executable("subfinder")
        dnsx_bin = resolve_executable("dnsx")
        if not subfinder_bin or not dnsx_bin:
            self.warning = "subfinder/dnsx not installed; discovery unavailable"
            self.detail = {"domain": domain, "mode": "unavailable"}
            return []

        subdomains = self._discover(subfinder_bin, domain, timeout)
        self.detail = {"domain": domain, "discovered": len(subdomains)}

        if not subdomains:
            self.warning = "subfinder returned no subdomains"
            return []

        live = self._resolve_live(dnsx_bin, subdomains, timeout)
        findings: List[RawFinding] = []
        for host, ip in live[:MAX_SUBDOMAIN_FINDINGS]:
            findings.append(
                RawFinding(
                    scanner="subdomains",
                    scanner_template_id="live-subdomain",
                    vulnerability_type="reconnaissance",
                    target=target,
                    host=host,
                    severity="info",
                    description=f"live subdomain discovered: {host}",
                    raw={"host": host, "ip": ip or None},
                )
            )
        if len(live) > MAX_SUBDOMAIN_FINDINGS:
            self.detail["truncated"] = len(live) - MAX_SUBDOMAIN_FINDINGS + " more live subdomains stored in scan data"
            self.detail["all_live"] = sorted(set(h for h, _ in live))
        return findings

    @staticmethod
    def _discover(subfinder_bin: str, domain: str, timeout: int) -> list[str]:
        try:
            proc = subprocess.run(
                [subfinder_bin, "-silent", "-d", domain, "-timeout", str(min(timeout, 90))],
                capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        if proc.returncode != 0:
            return []
        out = set()
        for line in proc.stdout.splitlines():
            host = line.strip().lower()
            if host and "." in host:
                out.add(host.rstrip("."))
        return sorted(out)

    @staticmethod
    def _resolve_live(dnsx_bin: str, hosts: list[str], timeout: int) -> list[tuple[str, Optional[str]]]:
        live: list[tuple[str, Optional[str]]] = []
        try:
            proc = subprocess.run(
                [dnsx_bin, "-silent", "-a", "-resp"],
                input="\n".join(hosts) + "\n",
                capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        for line in proc.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            host = parts[0].strip().lower().rstrip(".")
            ip = next((p.strip("[]") for p in parts[1:] if ":" not in p), None)
            if host:
                live.append((host, ip))
        return live