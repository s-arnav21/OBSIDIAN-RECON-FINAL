"""SMTP probe — banner, VRFY/EXPN user enumeration, open relay.

Gated on `port_25_open` / `port_587_open` / `port_465_open`. Connects with
smtplib (implicit TLS on 465) and:

  1. Calls VRFY on common usernames (and EXPN on one list) — 250/252
     responses reveal account names.
  2. Checks for an open relay by having external recipients accepted with
     250 on RCPT, then immediately issues RSET (no message is ever sent).

Findings: `smtp-open-relay` (HIGH), `smtp-user-enum` (MEDIUM), and an info
banner note. Server banner is always recorded on osint.
"""
from __future__ import annotations

import smtplib
from typing import List, NamedTuple, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PORTS = (25, 587, 465)
CONNECT_TIMEOUT = 12
_HELO = "recon.local"

_VRFY_USERS = ("root", "admin", "administrator", "postmaster", "info",
               "support", "sales", "webmaster", "test", "user")

_RELAY_FROM = "pinger@example.com"
_RELAY_TO = "pong@example.net"


class SmtpSession(NamedTuple):
    port: int
    banner: str
    ehlo_ok: bool


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _connect(host: str, port: int) -> Optional[smtplib.SMTP]:
    try:
        if port == 465:
            s = smtplib.SMTP_SSL(host, port, timeout=CONNECT_TIMEOUT)
        else:
            s = smtplib.SMTP(host, port, timeout=CONNECT_TIMEOUT)
        s.ehlo(_HELO)
        return s
    except Exception:  # noqa: BLE001
        return None


def _banner(s: smtplib.SMTP) -> Optional[str]:
    try:
        return (s.getwelcome() or "").strip()[:120] or None
    except Exception:  # noqa: BLE001
        try:
            return s.server_helo or None
        except Exception:  # noqa: BLE001
            return None


def _vrfy_scan(s: smtplib.SMTP) -> List[dict]:
    hits: List[dict] = []
    for user in _VRFY_USERS:
        for verb in ("VRFY", "EXPN"):
            try:
                code, _ = s.docmd(verb, user)
            except Exception:  # noqa: BLE001
                break
            if code in (250, 252):
                hits.append({"user": user, "verb": verb, "code": code})
                break
    return hits


def _relay_check(s: smtplib.SMTP) -> Optional[dict]:
    try:
        s.docmd("MAIL", f"FROM:<{_RELAY_FROM}>")
        rcpt_code, rcpt_msg = s.docmd("RCPT", f"TO:<{_RELAY_TO}>")
        s.docmd("RSET")
        if rcpt_code in (250, 251):
            return {"from": _RELAY_FROM, "to": _RELAY_TO,
                    "rcpt_code": rcpt_code,
                    "rcpt_message": (rcpt_msg or "")[:120]}
    except Exception:  # noqa: BLE001
        return None
    return None


@register
class SmtpProbeSkill(Skill):
    """Probe SMTP: banner, VRFY/EXPN enumeration, open relay."""

    name = "smtp-probe"
    display_name = "SMTP Probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = [f"port_{p}_open" for p in PORTS]

    timeout_seconds = 60
    max_requests = 30

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and any(
            p in ctx.open_ports for p in PORTS)

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"smtp_scan": "no-target"}})
        ports = [p for p in PORTS if p in ctx.open_ports] or PORTS[:1]

        findings: list[RawFinding] = []
        session: Optional[SmtpSession] = None
        for port in ports:
            s = _connect(host, port)
            if s is None:
                continue
            try:
                banner = _banner(s)
                session = SmtpSession(port, banner or "", True)
                hits = _vrfy_scan(s)
                relay = _relay_check(s)
            finally:
                try:
                    s.quit()
                except Exception:  # noqa: BLE001
                    try:
                        s.close()
                    except Exception:  # noqa: BLE001
                        pass

            if hits:
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="smtp-user-enum",
                    vulnerability_type="user_enumeration",
                    target=f"{host}:{port}", host=host,
                    severity="medium",
                    url=f"smtp://{host}:{port}/",
                    description=(
                        f"SMTP {host}:{port} discloses accounts via "
                        f"VRFY/EXPN: {', '.join(h['user'] for h in hits[:8])}"),
                    raw={"users": hits},
                ))
            if relay:
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="smtp-open-relay",
                    vulnerability_type="open_relay",
                    target=f"{host}:{port}", host=host,
                    severity="high",
                    url=f"smtp://{host}:{port}/",
                    description=(f"SMTP {host}:{port} accepted RCPT for "
                                 f"external address {_RELAY_TO} — open relay "
                                 f"candidate (aborted with RSET)"),
                    raw=relay,
                ))
            if banner:
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="smtp-service",
                    vulnerability_type="reconnaissance",
                    target=f"{host}:{port}", host=host,
                    severity="info",
                    url=f"smtp://{host}:{port}/",
                    description=f"SMTP banner on {host}:{port}: {banner!r}",
                    raw={"banner": banner},
                ))
            break  # one live session is enough for fingerprint class

        if session is None:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"smtp_scan": "unreachable"}})

        flagged = any(f.scanner_template_id in ("smtp-open-relay",
                                                 "smtp-user-enum")
                      for f in findings)
        if not flagged:
            return SkillResult(
                skill_name=self.name, success=True, findings=findings,
                context_updates={"osint": {"smtp_banner": session.banner,
                                           "smtp_scan": "clean"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "smtp_banner": session.banner,
                "smtp_open_relay": any(
                    f.scanner_template_id == "smtp-open-relay"
                    for f in findings),
                "smtp_user_enum": any(
                    f.scanner_template_id == "smtp-user-enum"
                    for f in findings),
                "smtp_scan": "flagged"}})