"""SMB probe — null-session (anonymous) access, share listing, EternalBlue
heuristic.

Gated on `port_445_open` / `port_139_open`. Two cooperating checks:

  1. Raw SMBv1 negotiate — confirms the service speaks SMB and yields the
     server identity (Windows vs Samba) by scanning the negotiate response;
     SMBv1 + a Windows identity is the precondition for the EternalBlue class
     and is surfaced (clearly labelled low-confidence).
  2. Null-session (anonymous) connect via pysmb — an anonymous logon with a
     share list is the classic unauthenticated information leak; every share
     name is reported.

`smb-null-session` is HIGH when an anonymous session yields shares;
`smb-protocol-flags` (INFO) records the negotiate result + identity. Nothing
external; pysmb is bundled.
"""
from __future__ import annotations

import socket
import struct
from typing import List, NamedTuple, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10

# SMBv1 Negotiate Protocol request (dialects NT LM 0.12, SMB 2.002, SMB 2.???).
_DIALECTS = (b"\x02NT LM 0.12\x02SMB 2.002\x02SMB 2.???"
             b"\x02SMB 2.1\x02SMB 3.0")

_HEADER = (
    b"\xff\x53\x4d\x42" +    # magic
    b"\x72" +                # SMB_COM_NEGOTIATE
    b"\x00\x00\x00\x00" +    # status
    b"\x18" +                # flags
    b"\x00\x00" +            # flags2
    b"\x00\x00" +            # pid high
    b"\x00" * 8 +            # signature
    b"\x00\x00" +            # reserved
    b"\x00\x00" +            # tid
    b"\x01\x00" +            # pid
    b"\x00\x00" +            # uid
    b"\x00\x00"              # mid
)

_NETBIOS_DIRECT_TCP = b"\x00"  # netbios session prefix for direct TCP (445)


class Negotiate(NamedTuple):
    ok: bool
    identity: str          # "windows" | "samba" | "unknown"
    dialect_index: int
    smbv1: bool


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _port(ctx: SkillContext) -> int:
    for p in (445, 139):
        if p in ctx.open_ports:
            return p
    return 445


def _smbv1_negotiate(host: str, port: int) -> Optional[Negotiate]:
    request = _HEADER + b"\x00" + struct.pack(">H", len(_DIALECTS)) + _DIALECTS
    if port == 445:
        request = _NETBIOS_DIRECT_TCP + request
    try:
        with socket.create_connection((host, port),
                                      timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(CONNECT_TIMEOUT)
            s.sendall(request)
            resp = s.recv(4096)
    except Exception:  # noqa: BLE001
        return None
    if len(resp) < 36 or not resp[:4].endswith(b"SMB"):
        return None
    dialect_index = struct.unpack("<H", resp[32:34])[0] if len(resp) >= 34 \
        else 0xFFFF
    ok = dialect_index != 0xFFFF
    smbv1 = ok and dialect_index < 2
    identity = "unknown"
    if b"Windows" in resp:
        identity = "windows"
    elif b"Samba" in resp or b"Unix" in resp:
        identity = "samba"
    return Negotiate(ok, identity, dialect_index, smbv1)


def _null_session_shares(host: str, port: int) -> List[dict]:
    """Attempt an anonymous SMB session; returns share dicts on success."""
    try:
        from smb.SMBConnection import SMBConnection
    except Exception:  # noqa: BLE001
        return []
    try:
        conn = SMBConnection("", "", "reconhost", "SMBSERVER",
                             domain="", use_ntlm_v2=True,
                             is_direct_tcp=port == 445)
        conn.connect(host, port, timeout=CONNECT_TIMEOUT)
        try:
            shares = conn.listShares(timeout=CONNECT_TIMEOUT) or []
            return [{"name": getattr(s, "name", ""),
                     "is_special": bool(getattr(s, "isSpecial", False)),
                     "is_disk": bool(getattr(s, "isDisk", False)),
                     "comment": (getattr(s, "comments", "") or "")[:80]}
                    for s in shares]
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        return []


@register
class SmbProbeSkill(Skill):
    """Probe SMB: negotiate ID + null-session share listing + EternalBlue
    heuristic."""

    name = "smb-probe"
    display_name = "SMB Probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_445_open", "port_139_open"]

    timeout_seconds = 45
    max_requests = 8

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and any(
            p in ctx.open_ports for p in (445, 139))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"smb_scan": "no-target"}})
        port = _port(ctx)

        neg = _smbv1_negotiate(host, port)
        if neg is None:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"smb_scan": "unreachable"}})

        findings: list[RawFinding] = []
        shares = _null_session_shares(host, port)

        is_win = neg.identity == "windows"
        is_samba = neg.identity == "samba"
        eternalblue_possible = neg.smbv1 and is_win
        samba_cry_possible = neg.smbv1 and is_samba  # CVE-2017-7494 heuristic

        if shares:
            names = [s["name"] for s in shares]
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="smb-null-session",
                vulnerability_type="weak_authentication",
                target=f"{host}:{port}", host=host,
                severity="high",
                url=f"smb://{host}:{port}/",
                description=(
                    f"SMB allows anonymous (null) session on {host}:{port} — "
                    f"shares readable: {', '.join(names[:8])}"
                    + ("; [EternalBlue heuristic: SMBv1 + Windows, "
                       "verify manually]" if eternalblue_possible else "")),
                raw={
                    "shares": shares,
                    "identity": neg.identity,
                    "smbv1_dialect_chosen": neg.smbv1,
                    "eternalblue_possible": eternalblue_possible,
                },
            ))
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="smb-protocol-flags",
                vulnerability_type="reconnaissance",
                target=f"{host}:{port}", host=host,
                severity="info",
                url=f"smb://{host}:{port}/",
                description=(
                    f"SMB service fingerprinted as {neg.identity}, "
                    f"SMBv1 dialect {neg.dialect_index}"),
                raw={"identity": neg.identity, "dialect_index": neg.dialect_index},
            ))

        # SambaCry (CVE-2017-7494) heuristic — SMBv1 + Samba identity.
        # Samba 3.0.20+ running SMBv1 is vulnerable to SambaCry which allows
        # remote code execution via a malicious .so file upload through the
        # write_access permitted in SMB share.
        if not shares and is_samba and neg.smbv1 and not findings:
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="samba-smbv1-heuristic",
                vulnerability_type="information-disclosure",
                target=f"{host}:{port}", host=host,
                severity="medium",
                url=f"smb://{host}:{port}/",
                description=(
                    f"Samba SMBv1 detected on {host}:{port} — CVE-2017-7494 "
                    f"(SambaCry) heuristic: Samba identity, SMBv1 negotiation "
                    f"accepted. No null session found but version is exploitable "
                    f"with valid credentials."),
                raw={"identity": neg.identity,
                     "smbv1_dialect": neg.dialect_index,
                     "cve": "CVE-2017-7494", "null_session": False},
            ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {
                    "smb_identity": neg.identity,
                    "smb_smbv1": neg.smbv1,
                    "smb_null_session": False,
                    "smb_cry_possible": samba_cry_possible,
                    "smb_scan": "clean"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "smb_identity": neg.identity,
                "smb_smbv1": neg.smbv1,
                "smb_null_session": bool(shares),
                "smb_cry_possible": samba_cry_possible,
                "smb_shares": [s["name"] for s in shares],
                "smb_eternalblue_possible": eternalblue_possible,
                "smb_scan": "null-session" if shares else "clean"}})