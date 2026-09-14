"""MySQL probe — default credentials + database listing.

Gated on `port_3306_open`. A raw handshake read yields the server version for
osint; then `pymysql` (bundled) tries a small set of well-known default admin
pairs. On a successful logon it runs `SHOW DATABASES` to enumerate the default
(forbidden on hardened setups, so failures there are ignored).

Findings: `mysql-default-creds` (CRITICAL) when default pair logs in;
`mysql-service` (INFO) records the reachable server banner.
"""
from __future__ import annotations

import socket
from typing import List, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10

_DEFAULT_PAIRS = (
    ("root", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("root", "mysql"),
    ("admin", "admin"),
    ("test", "test"),
    ("mysql", "mysql"),
    ("user", "user"),
)
MAX_PAIRS = 9


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _mysql_server_version(host: str, port: int) -> Optional[str]:
    """Read the server's version string from the raw handshake packet."""
    try:
        with socket.create_connection((host, port),
                                      timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(CONNECT_TIMEOUT)
            header = s.recv(5)
            if len(header) < 5:
                return None
            length = int.from_bytes(header[:3], "little")
            payload = header[4:4 + length]
            while len(payload) < length:
                chunk = s.recv(length - len(payload))
                if not chunk:
                    break
                payload += chunk
        if not payload:
            return None
        # payload[0] = protocol version, then NUL-terminated server version.
        return payload[1:].split(b"\0", 1)[0].decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def _try_default_creds(host: str, port: int) -> dict:
    """Try default MySQL pairs with pymysql; return hits + databases."""
    try:
        import pymysql
    except Exception:  # noqa: BLE001
        return {"hits": [], "databases": []}
    import pymysql

    for user, pwd in _DEFAULT_PAIRS[:MAX_PAIRS]:
        conn = None
        try:
            conn = pymysql.connect(
                host=host, port=port, user=user, password=pwd,
                connect_timeout=CONNECT_TIMEOUT, read_timeout=CONNECT_TIMEOUT,
                autocommit=True)
            dbs: List[str] = []
            try:
                with conn.cursor() as cur:
                    cur.execute("SHOW DATABASES")
                    dbs = [r[0] for r in cur.fetchall()][:30]
            except Exception:  # noqa: BLE001 — no SHOW privilege
                pass
            return {"hits": [{"username": user, "password": pwd}],
                    "databases": dbs}
        except Exception:  # noqa: BLE001 — auth denied / refused
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
    return {"hits": [], "databases": []}


@register
class MysqlProbeSkill(Skill):
    """Probe MySQL: default credentials and database enumeration."""

    name = "mysql-probe"
    display_name = "MySQL Probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_3306_open"]

    timeout_seconds = 90
    max_requests = MAX_PAIRS + 1

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 3306 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"mysql_scan": "no-target"}})
        port = 3306 if 3306 in ctx.open_ports else ctx.port or 3306

        version = _mysql_server_version(host, port)
        result = _try_default_creds(host, port)

        findings: list[RawFinding] = []
        if version:
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="mysql-service",
                vulnerability_type="reconnaissance",
                target=f"{host}:{port}", host=host,
                severity="info",
                url=f"mysql://{host}:{port}/",
                description=f"MySQL reachable on {host}:{port} "
                            f"(server {version[:40]})",
                raw={"server_version": version},
            ))
        if result["hits"]:
            hit = result["hits"][0]
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="mysql-default-creds",
                vulnerability_type="weak_credentials",
                target=f"{host}:{port}", host=host,
                severity="critical",
                url=f"mysql://{host}:{port}/",
                description=(f"MySQL accepts default credentials "
                             f"{hit['username']} / '{hit['password']}' on "
                             f"{host}:{port} — databases: "
                             f"{', '.join(result['databases'][:8]) or 'none'}"),
                raw={"username": hit["username"], "password": hit["password"],
                     "databases": result["databases"]},
            ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"mysql_scan": "clean",
                                           "mysql_version": version}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "mysql_version": version,
                "mysql_databases": result["databases"],
                "mysql_default_creds": bool(result["hits"]),
                "mysql_scan": "default-creds" if result["hits"] else "ok"}})