"""VNC probe — detect authentication type from the RFB handshake.

Gated on `port_5900_open`. Reads the 12-byte RFB version response, then
examines the security-type negotiation to determine whether the server
accepts no-auth (security type 1/None) or requires VNC password.

  - `vnc-no-auth`      HIGH:  the server permits access without any password.
  - `vnc-auth-required` INFO:  VNC password is required (expected posture).

Metasploitable 2 ships a VNC instance; this skill confirms whether the
password is actually required (vs. open to anyone).
"""
from __future__ import annotations

import socket
import struct
from typing import Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10
_RFB_MARKER = b"RFB "
_NO_AUTH_TYPE = 1
_VNC_AUTH_TYPE = 2
_TIGHT_AUTH_TYPE = 16


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _read_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        return None
    return buf if len(buf) == n else None


def _parse_security_type(raw: bytes, version: int) -> Optional[int]:
    """Extract the primary security type from the RFB security response.

    RFB 3.7+: a 1-byte length + N security type bytes.
    RFB 3.3:  a 4-byte security type (uint32).
    Returns the first (or only) security type, or None on parse failure.
    """
    if not raw:
        return None
    if version >= 37:
        n_types = raw[0]
        if n_types == 0:
            return None
        return raw[1] if len(raw) >= 2 else None
    # RFB 3.3
    if len(raw) >= 4:
        return struct.unpack(">I", raw[:4])[0]
    return raw[0]


@register
class VncProbeSkill(Skill):
    """Detect VNC authentication type: no-auth vs. password required."""

    name = "vnc-probe"
    display_name = "VNC auth probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_5900_open"]

    timeout_seconds = 20
    max_requests = 4

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 5900 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"vnc_scan": "no-target"}})

        try:
            sock = socket.create_connection((host, 5900), timeout=CONNECT_TIMEOUT)
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"vnc_scan": "unreachable"}})

        try:
            version_line = _read_exact(sock, 12)
            if not version_line or not version_line.startswith(_RFB_MARKER):
                return SkillResult(
                    skill_name=self.name, success=True, findings=[],
                    context_updates={"osint": {"vnc_scan": "not-rfb"}})

            version_str = version_line.decode("utf-8", errors="replace").strip()
            # Extract major.minor from "RFB 003.008" or "RFB 003.007"
            version_tokens = version_str.split()
            ver_major, ver_minor = 3, 3
            if len(version_tokens) >= 2:
                parts = version_tokens[1].split(".")
                if len(parts) == 2:
                    ver_major = int(parts[0]) if parts[0].isdigit() else 3
                    ver_minor = int(parts[1]) if parts[1].isdigit() else 3
            protocol_ver = ver_major * 10 + ver_minor  # 33 = 3.3, 38 = 3.8

            sec_raw: Optional[bytes]
            if protocol_ver == 33:
                sec_raw = _read_exact(sock, 4)
            else:
                # RFB 3.7+: read the length byte, then the type byte(s).
                n_bytes = _read_exact(sock, 1)
                n_types = n_bytes[0] if n_bytes else 0
                if n_types == 0:
                    sec_raw = None  # server refused, no auth type offered
                else:
                    types = _read_exact(sock, n_types)
                    sec_raw = (n_bytes if n_bytes is not None else b"") + (types or b"")
            if not sec_raw:
                return SkillResult(
                    skill_name=self.name, success=True, findings=[],
                    context_updates={"osint": {"vnc_scan": "no-security-types"}})

            sec_type = _parse_security_type(sec_raw, protocol_ver)
            no_auth = sec_type == _NO_AUTH_TYPE
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"vnc_scan": "handshake-error"}})
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

        auth_label = "None (no authentication)" if no_auth else "VNC password"
        severity = "high" if no_auth else "info"
        tid = "vnc-no-auth" if no_auth else "vnc-auth-required"

        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id=tid,
            vulnerability_type="weak_credentials" if no_auth else "reconnaissance",
            target=f"{host}:5900", host=host,
            port=5900,
            severity=severity,
            url=f"vnc://{host}:5900/",
            description=(
                f"VNC service on {host}:5900 uses authentication type {sec_type} "
                f"({auth_label}) — protocol version {version_tokens[1] if len(version_tokens) >= 2 else '?'}"
            ),
            raw={"version": version_str, "security_type": sec_type,
                 "no_auth": no_auth, "protocol_version": protocol_ver},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {
                "vnc_no_auth": no_auth,
                "vnc_security_type": sec_type,
                "vnc_scan": "no-auth" if no_auth else "auth-required"}})