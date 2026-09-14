"""Java RMI Registry probe — detect unauthenticated registry access.

Gated on `port_1099_open`. Connects to the RMI port and reads the JRMP
protocol header (the server first sends a 7-byte handshake or a version
response). If the server responds, the service is live and exposed; this
is a MEDIUM `java-rmi-exposed` finding.

GNU Classpath grmiregistry (Metasploitable's implementation) does NOT
enforce authentication on list operations; a registry with accessible
bindings enables remote method invocation and deserialization attacks.
"""
from __future__ import annotations

import socket
from typing import Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 12


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _read_bytes(sock: socket.socket, n: int, timeout: float = _READ_TIMEOUT) -> Optional[bytes]:
    buf = b""
    try:
        sock.settimeout(timeout)
        while len(buf) < n:
            chunk = sock.recv(min(4096, n - len(buf)))
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        pass
    return buf if buf else None


@register
class JavaRmiProbeSkill(Skill):
    """Detect exposed Java RMI Registry / GNU Classpath grmiregistry."""

    name = "java-rmi-probe"
    display_name = "Java RMI probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_1099_open"]

    timeout_seconds = 30
    max_requests = 4

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 1099 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"java_rmi_scan": "no-target"}})

        try:
            sock = socket.create_connection((host, 1099), timeout=CONNECT_TIMEOUT)
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"java_rmi_scan": "unreachable"}})

        try:
            # JRMI client handshake header: magic + version.
            # 0x4a 0x52 0x4d 0x49  ("JRMI")
            # version 0x00 0x01
            sock.sendall(b"JRMI\x00\x01")
            resp = _read_bytes(sock, 64)
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"java_rmi_scan": "no-response"}})
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

        if not resp or len(resp) < 2:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"java_rmi_scan": "empty-response"}})

        # RMIRegistry response: first byte 0x4e ('N') = protocol acknowledgment
        # GNU Classpath grmiregistry typically returns:
        #   0x4e + status + ...  (protocol ack)
        is_ack = resp[0] == 0x4e
        raw_hex = resp.hex()[:80]
        detected = "GNU Classpath grmiregistry" if is_ack else "unknown RMI registry"

        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="java-rmi-exposed",
            vulnerability_type="information_disclosure",
            target=f"{host}:1099", host=host,
            port=1099,
            severity="medium",
            url=f"rmi://{host}:1099/",
            description=(
                f"Java RMI Registry on {host}:1099 responded to JRMI handshake "
                f"({detected}). Unauthenticated registry access enables remote "
                f"method invocation and potential deserialization attacks."
            ),
            raw={"protocol_ack": is_ack, "response_hex": raw_hex,
                 "detected_service": detected, "response_bytes": len(resp)},
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={"osint": {
                "java_rmi_exposed": True,
                "java_rmi_service": detected,
                "java_rmi_scan": "exposed"}})