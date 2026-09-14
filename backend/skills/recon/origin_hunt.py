"""Origin-IP Hunt — find the real origin server behind a WAF/CDN.

When a WAF sits in front of the public hostname, the attacker's first move is to
find the *origin* IP that answers with the same content but accepts direct
connections — completely bypassing the WAF's protections.

This skill collects candidate origin IPs from three passive sources:
  1. SPF / MX records   — mailbox + sender infrastructure often shares the
                          origin netblock (ip4:, include: mechanisms, MX hosts).
  2. Certificate Transparency (crt.sh) — SAN names whose A records land on
                          real, WAF-free infrastructure.
  3. ViewDNS DNS history — previously-attached IPs that may still be live.

Candidate IPs are each probed with the public hostname's Host header; an IP
whose response fingerprints identically to the WAF-fronted site is treated as
a high-confidence origin.

Findings:
  - ORIGIN_IP_EXPOSED (HIGH) — direct origin IP that mirrors the public site
Context:
  - osint.origin_ip (list of confirmed origin IPs)
Tools: stdlib (socket/dns queries) + httpx
"""
from __future__ import annotations

import re
import socket
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TIMEOUT = 10
USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")
EXTERNAL_RPS_DELAY = 1.2
MAX_CANDIDATES = 30


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=False,
                        headers={"User-Agent": USER_AGENT}, verify=False)


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


def _public_ip(host: str) -> Optional[str]:
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None
    return ip if _is_routable(ip) else None


def _candidate_ips_from_spf(domain: str) -> set[str]:
    """Origin-netblock hints from SPF (TXT) and MX records."""
    import dns.resolver
    import dns.rdatatype
    ips: set[str] = set()

    def _add(host: str) -> None:
        ip = _public_ip(host)
        if ip:
            ips.add(ip)

    try:
        txts = dns.resolver.resolve(domain, "TXT", lifetime=8)
    except Exception:  # noqa: BLE001
        txts = []
    for ans in txts:
        text = " ".join(s.decode() if isinstance(s, bytes) else s
                        for s in ans.strings)
        if "v=spf1" not in text.lower():
            continue
        for m in re.finditer(r"ip4:(\d{1,3}(?:\.\d{1,3}){3})", text, re.I):
            if _is_routable(m.group(1)):
                ips.add(m.group(1))
        for m in re.finditer(r"\ba(?::([a-z0-9._-]+))?\b", text.lower()):
            _add((m.group(1) or domain).rstrip("."))
        for m in re.finditer(r"include:([a-z0-9._-]+)", text.lower()):
            _add(m.group(1).rstrip("."))

    try:
        mxs = dns.resolver.resolve(domain, "MX", lifetime=8)
    except Exception:  # noqa: BLE001
        mxs = []
    for mx in mxs:
        _add(str(mx.exchange).rstrip("."))

    return ips


def _candidate_ips_from_ct(domain: str) -> set[str]:
    """SAN names from crt.sh whose A records expose origin infrastructure."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    names: set[str] = set()
    try:
        import time
        with _client() as c:
            r = c.get(url, timeout=TIMEOUT)
            time.sleep(EXTERNAL_RPS_DELAY)
            data = r.json() if r.status_code == 200 else []
    except Exception:  # noqa: BLE001
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


def _candidate_ips_from_history(domain: str) -> set[str]:
    """Historical DNS via viewdns.info/iphistory (free scrape)."""
    url = f"https://viewdns.info/iphistory/?domain={domain}"
    ips: set[str] = set()
    try:
        import time
        with _client() as c:
            r = c.get(url, timeout=TIMEOUT)
            time.sleep(EXTERNAL_RPS_DELAY)
            text = r.text or ""
    except Exception:  # noqa: BLE001
        return set()
    for m in re.finditer(r"<td>(\d{1,3}(?:\.\d{1,3}){3})</td>", text):
        ip = m.group(1)
        if _is_routable(ip):
            ips.add(ip)
        if len(ips) >= MAX_CANDIDATES:
            break
    return ips


def _parse_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def _fingerprint(url: str) -> Optional[dict]:
    """Fetch a URL and return a (title, body-sha, content-length) fingerprint."""
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
    except Exception:  # noqa: BLE001
        return None


@register
class OriginHuntSkill(Skill):
    """Locate a high-confidence origin IP behind a WAF/CDN."""

    name = "origin-hunt"
    display_name = "Origin-IP Hunt"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = ["waf_detected"]

    timeout_seconds = 120
    max_requests = 40

    def should_run(self, ctx: SkillContext) -> bool:
        if not _extract_host(ctx):
            return False
        return bool(ctx.waf_detected)

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        findings: list[RawFinding] = []
        osint_add = {}

        if not host or _is_ip(host) or not ctx.waf_detected:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"origin_hunt_skipped": True}})

        candidates: set[str] = set()
        candidates |= _candidate_ips_from_spf(host)
        candidates |= _candidate_ips_from_ct(host)
        candidates |= _candidate_ips_from_history(host)

        osint_add["origin_candidates"] = sorted(candidates)

        scheme = ctx.scheme or "https"
        public_url = f"{scheme}://{host}"
        public_fp = _fingerprint(public_url)
        if not public_fp:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": osint_add})

        exposed: list[str] = []
        for ip in sorted(candidates):
            fp = _fingerprint(f"http://{ip}/")
            if fp and fp["sha"] == public_fp["sha"]:
                exposed.append(ip)
                findings.append(self._origin_finding(
                    host, ip, ctx.waf_provider, public_fp["title"]))
                if len(exposed) >= 5:
                    break

        osint_add["origin_ip"] = exposed
        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint_add})

    def _origin_finding(self, host: str, ip: str,
                        provider: Optional[str], title: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="origin-ip-exposed",
            vulnerability_type="reconnaissance",
            target=host, host=ip,
            severity="high",
            description=(
                f"origin IP exposed: {ip} fingerprints identically to "
                f"{host} (WAF/CDN bypass candidate)"
            ),
            raw={
                "origin_ip": ip,
                "host": host,
                "provider": provider or "unknown",
                "confidence": "high",
                "method": "fingerprint-match",
                "title": title,
            },
        )