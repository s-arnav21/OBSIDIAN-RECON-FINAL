"""SNMP probe — default community strings over raw SNMPv1.

Gated on `port_161_open` (UDP). Without any SNMP library, a SNMPv1
GET(sysDescr.0) request is built by hand (BER/TLV) and sent over a UDP socket
to each of `public` / `private` / `community`. A clean response with
error-status 0 proves the community string is accepted and returns the value.

Findings: `snmp-default-community` (HIGH) for an accepted community on the
default/weak list.
"""
from __future__ import annotations

import socket
import struct
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

_COMMUNITIES = ("public", "private", "community")
_UDP_TIMEOUT = 4.0
_SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


# -- BER/TLV encoding -------------------------------------------------------

def _len_bytes(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len_bytes(len(content)) + content


def _int_tlv(value: int) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=False)
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _oid_bytes(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        return b""
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = []
        while True:
            chunk.insert(0, p & 0x7F)
            p >>= 7
            if p == 0:
                break
        for i, c in enumerate(chunk):
            if i < len(chunk) - 1:
                c |= 0x80
            body.append(c)
    return bytes(body)


def _varbind(oid: str) -> bytes:
    return _tlv(0x30, _tlv(0x06, _oid_bytes(oid)) + b"\x05\x00")


def _build_get_request(community: str, request_id: int = 0x1BADCAFE) -> bytes:
    pdu = _tlv(0xA0, _int_tlv(request_id) + _int_tlv(0) + _int_tlv(0) +
               _tlv(0x30, _varbind(_SYSDESCR_OID)))
    return _tlv(0x30, _int_tlv(0) + _tlv(0x04, community.encode()) + pdu)


# -- BER/TLV decoding -------------------------------------------------------

def _parse_len(data: bytes, i: int) -> Tuple[int, int]:
    first = data[i]
    i += 1
    if not first & 0x80:
        return first, i
    n = first & 0x7F
    if n > 8:
        return -1, i
    return int.from_bytes(data[i:i + n], "big"), i + n


def _parse_response(data: bytes) -> Optional[dict]:
    """Decode an SNMPv1 response into {pdu_tag, error_status, value}."""
    try:
        if data[0] != 0x30:
            return None
        _, i = _parse_len(data, 1)
        if data[i] != 0x02:           # version
            return None
        _, i = _skip(data, i)
        if data[i] != 0x04:           # community
            return None
        _, i = _skip(data, i)
        pdu_tag = data[i]
        if pdu_tag not in (0xA0, 0xA2):  # GetResponse / error PDU
            return None
        _, i = _parse_len(data, i + 1)   # descend into PDU content
        _, i = _read_int(data, i)        # request-id
        error_status, i = _read_int(data, i)  # error-status
        _, i = _read_int(data, i)        # error-index
        if data[i] != 0x30:              # varbind list
            return None
        _, i = _parse_len(data, i + 1)   # descend into varbind list
        if data[i] != 0x30:              # first varbind
            return None
        _, i = _parse_len(data, i + 1)   # descend into varbind
        if data[i] != 0x06:              # oid
            return None
        _, i = _skip(data, i)            # past oid value
        value_tag = data[i]
        vlen, _ = _parse_len(data, i + 1)
        value = data[i + 2:i + 2 + vlen]
        return {"pdu_tag": pdu_tag, "error_status": error_status,
                "value_tag": value_tag, "value": value}
    except (IndexError, ValueError):
        return None


def _skip(data: bytes, i: int) -> Tuple[int, int]:
    """Given index at a tag byte, return index after its full value."""
    length, j = _parse_len(data, i + 1)
    return i, j + length


def _read_int(data: bytes, i: int) -> Tuple[int, int]:
    """Read a BER INTEGER at index `i`; returns (value, index-after)."""
    if data[i] != 0x02:
        raise ValueError("not an integer")
    length, j = _parse_len(data, i + 1)
    return int.from_bytes(data[j:j + length], "big"), j + length


# -- network ----------------------------------------------------------------

def _community_probe(host: str, port: int, community: str) -> Optional[dict]:
    request = _build_get_request(community)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_UDP_TIMEOUT)
        sock.sendto(request, (host, port))
        data, _ = sock.recvfrom(65535)
    except (OSError, socket.timeout):
        return None
    finally:
        if sock:
            sock.close()
    return _parse_response(data)


@register
class SnmpProbeSkill(Skill):
    """Probe SNMP with default community strings."""

    name = "snmp-probe"
    display_name = "SNMP Probe"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = ["port_161_open"]

    timeout_seconds = 45
    max_requests = len(_COMMUNITIES)

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and 161 in ctx.open_ports

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"snmp_scan": "no-target"}})
        port = 161 if 161 in ctx.open_ports else ctx.port or 161

        accepted: List[dict] = []
        for community in _COMMUNITIES:
            res = _community_probe(host, port, community)
            if res and res["pdu_tag"] == 0xA2 and res["error_status"] == 0:
                value = res["value"]
                try:
                    descr = value.decode("utf-8", "replace").strip()[:160]
                except Exception:  # noqa: BLE001
                    descr = ""
                accepted.append({"community": community,
                                 "sys_descr": descr,
                                 "oid": _SYSDESCR_OID})
                break

        if not accepted:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"snmp_scan": "no-accept"}})

        found = accepted[0]
        findings = [RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="snmp-default-community",
            vulnerability_type="weak_authentication",
            target=f"{host}:{port}", host=host,
            severity="high",
            url=f"udp://{host}:{port}/",
            description=(f"SNMP accepts default community "
                         f"'{found['community']}' on {host}:{port} — "
                         f"agent info readable: {found['sys_descr'][:80] or '?'}"),
            raw=found,
        )]

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "snmp_community": found["community"],
                "snmp_sys_descr": found["sys_descr"],
                "snmp_scan": "default-community"}})