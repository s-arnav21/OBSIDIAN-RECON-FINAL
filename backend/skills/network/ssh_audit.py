"""SSH audit — banner + version, weak-crypto fingerprint, default credentials.

Gated on `port_22_open`. Steps:

  1. Banner grab over a raw socket — gives the exact server software version.
  2. Weak crypto flag — a deterministic version benchmark (OpenSSH before
     7.4 / Dropbear before 2020.79 ship legacy KEX/cipher algorithms).
  3. Default credentials — when `paramiko` is available, authenticates a
     small set of well-known default admin pairs (root/toor, admin/admin,
     pi/raspberry, …) directly over SSH.

Findings: `ssh-default-creds` (CRITICAL) when a pair logs in, `ssh-weak-crypto`
(LOW) for legacy-version servers. The banner and version are always recorded on
osint. Every failure degrades silently.
"""
from __future__ import annotations

import re
import socket
from typing import List, NamedTuple, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10
BANNER_READ_TIMEOUT = 10

_BANNER_RE = re.compile(
    r"SSH-[0-9]+\.[0-9]+-(OpenSSH(?:_\d+(\.\d+)*)?|Dropbear(?:_\d+(\.\d+)?)?|"
    r"[A-Za-z0-9._/+-]+)", re.I)

_WEAK_MARKERS = (
    ("openssh", 7, 4),
    ("dropbear", 2020, 79),
)

_DEFAULT_PAIRS = (
    ("root", "toor"),
    ("root", "root"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "password"),
    ("ubuntu", "ubuntu"),
    ("test", "test"),
    ("pi", "raspberry"),
    ("user", "user"),
    ("vagrant", "vagrant"),
)
MAX_PAIRS = 9


class Banner(NamedTuple):
    raw: str
    software: str
    major: int
    minor: int


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _grab_banner(host: str, port: int) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(BANNER_READ_TIMEOUT)
            # Server sends its banner first in SSH.
            data = b""
            while b"\n" not in data and len(data) < 512:
                chunk = s.recv(256)
                if not chunk:
                    break
                data += chunk
            return data.decode("utf-8", "replace").strip()
    except Exception:  # noqa: BLE001
        return None


def _parse_banner(banner: str) -> Optional[Banner]:
    m = _BANNER_RE.search(banner or "")
    if not m:
        return None
    software = m.group(1)
    parts = re.findall(r"(\d+)", software.split("_", 1)[-1])
    if not parts:
        return None
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return None
    return Banner(banner, re.sub(r"(OpenSSH|Dropbear)", lambda x: x.group(1),
                                 software).split("_")[0].split("-")[-1].strip()
                  or software, major, minor)


def _weak_crypto(banner: Optional[Banner]) -> Optional[str]:
    """Return a weak-crypto label when the server version is old enough to
    ship legacy KEX algorithms; None otherwise."""
    if banner is None:
        return None
    soft = banner.software.lower()
    for name, weak_major, weak_minor in _WEAK_MARKERS:
        if name not in soft:
            continue
        if banner.major < weak_major or (
                banner.major == weak_major and banner.minor < weak_minor):
            return f"{name}-{banner.major}.{banner.minor}"
    return None


def _try_default_creds(host: str, port: int) -> List[dict]:
    """Attempt _DEFAULT_PAIRS via paramiko; returns successful pairs."""
    try:
        import paramiko  # noqa: F401
    except Exception:  # noqa: BLE001
        return []
    import paramiko

    hits: List[dict] = []
    for user, pwd in _DEFAULT_PAIRS[:MAX_PAIRS]:
        transport = None
        try:
            transport = paramiko.Transport((host, port))
            transport.banner_timeout = CONNECT_TIMEOUT
            transport.start_client(timeout=CONNECT_TIMEOUT)
            transport.auth_password(user, pwd)
            hits.append({"username": user, "password": pwd})
            transport.close()
            break
        except paramiko.AuthenticationException:
            pass
        except Exception:  # noqa: BLE001 — connect refused, etc.
            break
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:  # noqa: BLE001
                    pass
    return hits


@register
class SshAuditSkill(Skill):
    """Audit SSH: banner/version, weak crypto, default credentials."""

    name = "ssh-audit"
    display_name = "SSH Audit"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_22_open"]

    timeout_seconds = 120
    max_requests = 12

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 22 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"ssh_scan": "no-target"}})
        port = 22 if 22 in ctx.open_ports else ctx.port or 22

        raw_banner = _grab_banner(host, port)
        if raw_banner is None:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"ssh_scan": "unreachable"}})
        banner = _parse_banner(raw_banner)

        findings: list[RawFinding] = []
        weak = _weak_crypto(banner)
        if weak:
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="ssh-weak-crypto",
                vulnerability_type="weak_crypto",
                target=f"{host}:{port}", host=host,
                severity="low",
                url=f"ssh://{host}:{port}/",
                description=(
                    f"SSH server {banner.raw[:60]!r} is old enough to ship "
                    "legacy KEX/cipher algorithms (weak crypto fingerprint)"),
                raw={"banner": banner.raw, "software": banner.software,
                     "version": f"{banner.major}.{banner.minor}",
                     "weak_label": weak},
            ))

        hits = _try_default_creds(host, port)
        for hit in hits:
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="ssh-default-creds",
                vulnerability_type="weak_credentials",
                target=f"{host}:{port}", host=host,
                severity="critical",
                url=f"ssh://{host}:{port}/",
                description=(
                    f"SSH accepts default credentials {hit['username']} / "
                    f"{hit['password']} on {host}:{port}"),
                raw={"username": hit["username"], "password": hit["password"]},
            ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {
                    "ssh_banner": banner.raw if banner else raw_banner,
                    "ssh_scan": "clean"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "ssh_banner": banner.raw if banner else raw_banner,
                "ssh_weak_crypto": weak or False,
                "ssh_default_creds": hits,
                "ssh_scan": "flagged"}})