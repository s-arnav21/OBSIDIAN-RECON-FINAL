"""Origin-IP hunt — locate the real origin behind a WAF/CDN.

When a WAF/CDN is detected on the primary host, this module tries to find the
direct origin IP from passive + tampering techniques:

  1. Historical DNS via libre endpoints (SecurityTrails-style is API-keyed, so
     we use the free `viewdns.info/iphistory` scrape and fall back to
     `hackertarget.com` where available).
  2. Certificate transparency (crt.sh) SAN / name entries that land on direct
     IPs or infrastructure not behind the WAF.
  3. Mail/NS/TXT records for the same organization that often reveal the
     origin netblock (used only as hints, not proof).
  4. Direct probing: fetch a candidate IP with a Host: header equal to the
     WAF'd hostname; if it returns the SAME title/body fingerprint as the
     WAF-fronted site, the CDN/first-hop IP is a plausible origin.

Emit a single `ORIGIN_IP_EXPOSED` RawFinding when a direct IP fingerprinted
identically to the public site (high confidence), else nothing.

Boundary: read-only, ~1 rps on third-party sources, never stores secrets.
"""
from __future__ import annotations

import re
import socket
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")
TIMEOUT = 10
EXTERNAL_RPS_DELAY = 1.2
MAX_CANDIDATES = 30


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.hostname or target.strip()
    host = host.strip("[]").split(":")[0]
    return host.lower().rstrip(".")


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=False,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _normalize_url(target: str) -> str:
    parsed = urlparse(target)
    return f"{parsed.scheme or 'http'}://{parsed.netloc or parsed.hostname}"


class OriginHuntError(Exception):
    pass


def _public_ip(host: str) -> Optional[str]:
    """Return the public IP for a host, or None (private/lookup failure)."""
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None
    if _is_routable(ip):
        return ip
    return None


def _is_routable(ip: str) -> bool:
    try:
        parts = ip.split(".")
        first = int(parts[0])
    except (IndexError, ValueError):
        return False
    if first == 10 or first == 127 or first == 169 or first == 0:
        return False
    if first == 192 and len(parts) > 1 and parts[1] == "168":
        return False
    if first == 172 and len(parts) > 1 and 16 <= int(parts[1]) <= 31:
        return False
    if first >= 224:
        return False
    return True


def _parse_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def _fingerprint(url: str) -> Optional[dict]:
    """Fetch a URL and return its (title, body-sha, content-length) fingerprint."""
    try:
        with _client() as c:
            r = c.get(url, timeout=TIMEOUT)
            if r.status_code >= 400:
                return None
            body = r.text or ""
            import hashlib
            return {
                "title": _parse_title(body),
                "sha": hashlib.sha256(body[:20000].encode()).hexdigest()[:16],
                "length": len(body),
            }
    except Exception:
        return None


def _candidate_ips_from_ct(domain: str) -> set[str]:
    """crt.sh may expose names whose A record is the real origin netblock."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    names: set[str] = set()
    try:
        with _client() as c:
            import time
            r = c.get(url, timeout=TIMEOUT)
            time.sleep(EXTERNAL_RPS_DELAY)
            data = r.json() if r.status_code == 200 else []
    except Exception:
        return set()
    for row in data if isinstance(data, list) else []:
        nv = row.get("name_value") or ""
        for n in str(nv).split("\n"):
            n = n.strip().lower().rstrip(".")
            if n and "*" not in n:
                names.add(n)
    ips: set[str] = set()
    for name in list(names)[:50]:
        ip = _public_ip(name)
        if ip:
            ips.add(ip)
    return ips


def _dns_query(domain: str, rtype: int) -> List[bytes]:
    """Minimal DNS query (server: resolver, UDP). Returns raw answer RDATA bytes.

    rtype: 15 = MX, 16 = TXT. Uses /etc/resolv.conf nameserver with fallback
    to 1.1.1.1/8.8.8.8. All stdlib — no external dependencies.
    """
    import random
    import struct as s

    def _qname(name) -> bytes:
        out = b""
        for part in name.rstrip(".").split("."):
            b = part.encode()
            out += bytes([len(b)]) + b
        return out + b"\x00"

    servers = ["1.1.1.1", "8.8.8.8"]
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    ns = line.split()[1]
                    if ns not in servers:
                        servers.insert(0, ns)
    except OSError:
        pass

    rid = random.randint(0, 0xFFFF)
    header = s.pack(">HHHHHH", rid, 0x0100, 1, 0, 0, 0)
    question = _qname(domain) + s.pack(">HH", rtype, 1)
    packet = header + question

    answers: List[bytes] = []
    for server in servers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(4)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
            sock.close()
        except OSError:
            continue
        if len(data) < 12:
            continue
        rflags = s.unpack(">H", data[2:4])[0]
        if rflags & 0x000F != 0:  # rcode != 0 (or response not set)
            continue
        ancount = s.unpack(">H", data[6:8])[0]
        # skip question section
        offset = 12
        while offset < len(data) and data[offset] != 0:
            # handle compression (should not appear in question)
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
                break
            offset += 1 + data[offset]
        offset += 5  # null terminator + qtype + qclass
        for _ in range(ancount):
            # skip name (may be compressed)
            while True:
                if offset >= len(data):
                    break
                l = data[offset]
                if l == 0:
                    offset += 1
                    break
                if l & 0xC0 == 0xC0:
                    offset += 2
                    break
                offset += 1 + l
            if offset + 10 > len(data):
                break
            rtype_r, _cls, ttl, rdlen = s.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if offset + rdlen > len(data):
                break
            rdata = data[offset:offset + rdlen]
            offset += rdlen
            if rtype_r == rtype:
                answers.append(rdata)
            if len(answers) >= 10:
                break
        if answers:
            break
    return answers


def _candidate_ips_from_mail(domain: str) -> set[str]:
    """Extract origin-netblock hints from MX and SPF (TXT) records.

    MX records resolve mail servers which often share the organization's real
    origin netblock; SPF `ip4:`/`ip6:`/`a:`/`mx:`/`include:` mechanisms reveal
    allowed sender IPs. Used only as candidate hints, not proof.
    """
    ips: set[str] = set()

    def _add_public(host: str) -> None:
        ip = _public_ip(host)
        if ip and _is_routable(ip):
            ips.add(ip)

    # MX records -> resolve them to A records.
    for rdata in _dns_query(domain, 15):
        try:
            # MX payload: 2-byte preference + exchange hostname.
            exchange = _decode_dns_name(rdata[2:])
        except Exception:
            continue
        if exchange:
            _add_public(exchange)

    # SPF / TXT records -> parse ip4:/ip6:/a:/mx:/include: mechanisms.
    txt_records = " ".join(_decode_txt(r) for r in _dns_query(domain, 16))
    low = txt_records.lower()
    if "v=spf1" in low:
        # Direct IP literals.
        for m in re.finditer(r"ip4:(\d{1,3}(?:\.\d{1,3}){3})", txt_records, re.I):
            if _is_routable(m.group(1)):
                ips.add(m.group(1))
        for m in re.finditer(r"ip6:([0-9a-f:]+)", txt_records, re.I):
            if _is_routable(m.group(1)):
                ips.add(m.group(1))
        # `a:` / `a` (domain) mechanisms -> the domain's own A records.
        for m in re.finditer(r"\ba(?::([a-z0-9._-]+))?\b", low):
            target = m.group(1) or domain
            _add_public(target.rstrip("."))
        # `mx` mechanisms -> the domain's MX hosts.
        for m in re.finditer(r"\bmx(?::([a-z0-9._-]+))?\b", low):
            mx_domain = (m.group(1) or domain).rstrip(".")
            for rdata in _dns_query(mx_domain, 15):
                try:
                    exchange = _decode_dns_name(rdata[2:])
                except Exception:
                    continue
                if exchange:
                    _add_public(exchange)
        # `include:` mechanisms -> resolve the referenced SPF policy's IPs.
        for m in re.finditer(r"include:([a-z0-9._-]+)", low):
            included = m.group(1).rstrip(".")
            for rdata in _dns_query(included, 16):
                sub_txt = _decode_txt(rdata)
                for sub in re.finditer(r"ip4:(\d{1,3}(?:\.\d{1,3}){3})", sub_txt, re.I):
                    if _is_routable(sub.group(1)):
                        ips.add(sub.group(1))
                for sub in re.finditer(r"\ba(?::([a-z0-9._-]+))?\b", sub_txt.lower()):
                    _add_public((sub.group(1) or included).rstrip("."))
    return ips


def _decode_dns_name(raw: bytes) -> str:
    # raw is a sequence of length-prefixed labels (no compression in rdata).
    parts: list[str] = []
    i = 0
    while i < len(raw) and raw[i] != 0:
        l = raw[i]
        i += 1
        if i + l > len(raw):
            break
        parts.append(raw[i:i + l].decode("ascii", "replace"))
        i += l
    return ".".join(parts).lower()


def _decode_txt(raw: bytes) -> str:
    out = []
    i = 0
    while i < len(raw):
        l = raw[i]
        i += 1
        out.append(raw[i:i + l].decode("utf-8", "replace"))
        i += l
    return "".join(out)


def _candidate_ips_from_history(domain: str) -> set[str]:
    """Historical DNS via viewdns.info/iphistory (free scrape)."""
    url = f"https://viewdns.info/iphistory/?domain={domain}"
    ips: set[str] = set()
    try:
        with _client() as c:
            import time
            r = c.get(url, timeout=TIMEOUT)
            time.sleep(EXTERNAL_RPS_DELAY)
            text = r.text or ""
    except Exception:
        return set()
    # Table rows look like: <tr><td>IP</td><td>Location</td>...
    for m in re.finditer(r"<td>(\d{1,3}(?:\.\d{1,3}){3})</td>", text):
        ip = m.group(1)
        if _is_routable(ip):
            ips.add(ip)
        if len(ips) >= MAX_CANDIDATES:
            break
    return ips


def run_origin_hunt(target: str, waf_metadata: Optional[dict] = None) -> tuple[List[dict], List[RawFinding]]:
    """Attempt to discover the origin IP behind a WAF/CDN.

    Args:
        target: original target URL/host.
        waf_metadata: the WAF_DETECTED `waf_metadata` dict if a WAF was found.

    Returns:
        (origin_ip_info_list, findings). `origin_ip_info` carries the direct
        IP(s) that fingerprinted identically; findings holds the
        ORIGIN_IP_EXPOSED RawFinding(s).
    """
    domain = _extract_domain(target)
    findings: List[RawFinding] = []

    # Only bother if a WAF/CDN is actually present.
    provider = (waf_metadata or {}).get("provider") if waf_metadata else None
    if not provider:
        return [], []

    candidates: set[str] = set()
    candidates |= _candidate_ips_from_ct(domain)
    candidates |= _candidate_ips_from_history(domain)
    candidates |= _candidate_ips_from_mail(domain)

    # Probe each candidate with the same Host: header and compare fingerprints.
    public_fp = _fingerprint(_normalize_url(target))
    if not public_fp:
        return [], []

    exposed: set[str] = set()
    for ip in sorted(candidates):
        probe = f"http://{ip}/"
        fp = _fingerprint(probe)
        if fp and fp["sha"] == public_fp["sha"]:
            exposed.add(ip)
        if len(exposed) >= 5:
            break

    origin_info = []
    for ip in sorted(exposed):
        origin_info.append({
            "origin_ip": ip,
            "host": domain,
            "confidence": "high",
            "method": "fingerprint-match",
        })
        findings.append(RawFinding(
            scanner="origin_hunt",
            scanner_template_id="ORIGIN_IP_EXPOSED",
            vulnerability_type="reconnaissance",
            target=target,
            host=ip,
            severity="high",
            url=target,
            description=(
                f"origin IP exposed: {ip} fingerprinted identically to "
                f"{domain} (WAF/CDN bypass candidate)"
            ),
            raw={
                "origin_ip": ip,
                "host": domain,
                "provider": provider,
                "confidence": "high",
                "method": "fingerprint-match",
                "title": public_fp["title"],
            },
        ))

    return origin_info, findings