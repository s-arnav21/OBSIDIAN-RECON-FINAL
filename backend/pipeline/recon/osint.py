"""OSINT passive reconnaissance enrichment (Stage 1 extension).

Pulls passive, non-intrusive data about a target domain using free HTTP/API
sources (no auth keys required) and attaches results to the Asset object:

  - WHOIS            via the `python-whois` library
  - Certificate      via crt.sh certificate-transparency JSON API
                     (also yields the SAN / subjectAltName list)
  - Reverse-IP       via hackertarget.com free reverse-IP-lookup
  - Historical URLs  via web.archive.org CDX API (path + collapse=urlkey)

Callers get two things back:
  1. An `OsintResult` dict with structured fields for attaching to Asset.
  2. A list of high-value `RawFinding`s surfaced from that data
     (expiring/expired cert, internal hostname leaked in SAN, co-hosted
     domains with different risk, historical exposed paths).

Boundary / safety:
  - Only read-only public sources, ~1 rps, 10s timeout, fixed UA.
  - No secrets are stored; findings carry only structural metadata.
  - Any failing source degrades gracefully and never blocks recon.
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")
TIMEOUT = 10
EXTERNAL_RPS_DELAY = 1.05


@dataclass
class OsintResult:
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiry_date: Optional[str] = None
    whois_org: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    san_names: List[str] = field(default_factory=list)
    reverse_ips: List[str] = field(default_factory=list)
    historical_urls: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    errors: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "creation_date": self.creation_date,
            "expiry_date": self.expiry_date,
            "whois_org": self.whois_org,
            "nameservers": self.nameservers,
            "san_names": self.san_names,
            "reverse_ips": self.reverse_ips,
            "historical_urls": self.historical_urls[:100],
            "sources": self.sources,
            "errors": self.errors,
        }


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.hostname or target.strip()
    host = host.strip("[]").split(":")[0]
    return host.lower().rstrip(".")


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


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


# ---- individual sources ----

def _whois(domain: str, res: OsintResult) -> None:
    try:
        import whois as _whois
        w = _whois.whois(domain)
    except Exception as exc:  # noqa: BLE001
        res.errors["whois"] = type(exc).__name__
        return
    res.sources.append("whois")
    res.registrar = _first(w.registrar)
    res.whois_org = _first(w.org) or _first(w.name)
    res.creation_date = _fmt_date(_first(w.creation_date))
    res.expiry_date = _fmt_date(_first(w.expiration_date))
    ns = w.nameservers
    if isinstance(ns, list):
        res.nameservers = [str(n).strip().lower().rstrip(".") for n in ns][:10]


def _crt_sh(domain: str, res: OsintResult) -> None:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with _client() as c:
            import time
            r = c.get(url, timeout=TIMEOUT)
            time.sleep(EXTERNAL_RPS_DELAY)
            if r.status_code != 200:
                res.errors["crt.sh"] = f"http {r.status_code}"
                return
            data = r.json()
    except Exception as exc:  # noqa: BLE001
        res.errors["crt.sh"] = type(exc).__name__
        return
    if not isinstance(data, list):
        res.errors["crt.sh"] = "not a list"
        return
    res.sources.append("crt.sh")
    names: set[str] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        nv = row.get("name_value") or row.get("common_name") or ""
        for n in str(nv).split("\n"):
            n = n.strip().lower().rstrip(".")
            if n and "*" not in n:
                names.add(n)
    res.san_names = sorted(names)[:100]


def _reverse_ip(domain: str, res: OsintResult) -> None:
    url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}"
    try:
        with _client() as c:
            import time
            r = c.get(url, timeout=TIMEOUT)
            time.sleep(EXTERNAL_RPS_DELAY)
            text = r.text or ""
    except Exception as exc:  # noqa: BLE001
        res.errors["reverse-ip"] = type(exc).__name__
        return
    if "error" in text.lower() or "api count exceeded" in text.lower():
        res.errors["reverse-ip"] = "quota/blocked"
        return
    res.sources.append("reverse-ip")
    hosts = [h.strip().lower().rstrip(".") for h in text.strip().splitlines() if h.strip()]
    res.reverse_ips = hosts[:100]


def _historic_urls(domain: str, res: OsintResult) -> None:
    url = (
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&"
        f"output=json&fl=original&collapse=urlkey&limit=500"
    )
    try:
        with _client() as c:
            import time
            r = c.get(url, timeout=TIMEOUT)
            time.sleep(EXTERNAL_RPS_DELAY)
            text = r.text or ""
    except Exception as exc:  # noqa: BLE001
        res.errors["wayback"] = type(exc).__name__
        return
    try:
        import json
        rows = json.loads(text)
    except Exception:
        res.errors["wayback"] = "bad json"
        return
    res.sources.append("wayback")
    seen: set[str] = set()
    urls: list[str] = []
    for row in rows:
        if not isinstance(row, list) or not row:
            continue
        u = row[0]
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
            if len(urls) >= 300:
                break
    res.historical_urls = urls


# ---- helpers ----

def _first(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _fmt_date(value) -> Optional[str]:
    if not value:
        return None
    try:
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        return str(value)
    except Exception:
        return str(value)


def _is_internal(host: str) -> bool:
    low = host.lower()
    if low.startswith(("localhost", "dev", "staging", "test", "internal", "int-")):
        return True
    if any(k in low for k in (".local", ".internal", ".lan", ".corp", ".private")):
        return True
    try:
        ip = socket.inet_aton(host.split("/")[0])
        first = (ip[0], ip[1], ip[2])
        if ip[0] == 10 or (ip[0] == 172 and 16 <= ip[1] <= 31) or (ip[0] == 192 and ip[1] == 168):
            return True
        if ip[0] == 127:
            return True
    except OSError:
        pass
    return False


def run_osint(target: str) -> tuple[OsintResult, List[RawFinding]]:
    """Run all OSINT sources for a target.

    Returns (OsintResult, high_value_findings). Never raises: each source is
    isolated and errors are recorded in `OsintResult.errors`.
    """
    domain = _extract_domain(target)
    res = OsintResult(domain=domain)
    findings: List[RawFinding] = []

    if _is_ip(domain):
        return res, findings

    _whois(domain, res)
    _crt_sh(domain, res)
    _reverse_ip(domain, res)
    _historic_urls(domain, res)

    # --- surface high-value findings ---
    if res.expiry_date:
        try:
            exp = datetime.fromisoformat(res.expiry_date)
            days_left = (exp.date() - date.today()).days
            if days_left < 0:
                findings.append(_osint_finding(
                    domain, "osint-cert-expired", "high",
                    "domain registration has EXPIRED",
                    {"expiry_date": res.expiry_date}))
            elif days_left < 90:  # P2.3 DOMAIN_EXPIRING_SOON (<90 days)
                findings.append(_osint_finding(
                    domain, "osint-domain-expiring", "low",
                    f"domain registration expires in {days_left} days",
                    {"expiry_date": res.expiry_date, "days_left": days_left}))
        except (ValueError, TypeError):
            pass

    for name in res.san_names:
        if _is_internal(name):
            findings.append(_osint_finding(
                domain, "osint-internal-san", "medium",
                f"internal hostname leaked in certificate SAN: {name}",
                {"san_name": name}))
            break  # one finding per scan is enough for this class
        # P2.3 IP_IN_CERT_SAN: an IP literal embedded in a certificate SAN.
        if _is_ip(name.rstrip(".")):
            findings.append(_osint_finding(
                domain, "osint-ip-in-cert-san", "low",
                f"IP address leaked in certificate SAN: {name}",
                {"san_name": name}))
            break

    # P2.3 HISTORICAL_SENSITIVE_PATH: archived URLs exposing sensitive paths.
    sensitive = re.compile(
        r"(?i)(/\.env|/\.git|/config\.|/wp-config|/backup|/db\.sql|"
        r"/\.ssh|/id_rsa|/\.aws|\.bak$|~$|\.old$|\.log$|/admin|/debug)"
    )
    for url in res.historical_urls:
        if sensitive.search(url):
            findings.append(_osint_finding(
                domain, "osint-historical-sensitive-path", "low",
                f"sensitive path previously exposed publicly: {url[:120]}",
                {"url": url[:500]}))
            break

    # P2.3 SHARED_HOSTING_DETECTED: multiple nameservers / pan-ASN reverse-IP
    # implies third-party shared hosting in front of the origin.
    if len(res.nameservers) >= 2:
        findings.append(_osint_finding(
            domain, "osint-shared-hosting-detected", "info",
            "multiple nameservers suggest third-party managed/shared hosting",
            {"nameservers": res.nameservers}))

    return res, findings


def _osint_finding(domain: str, tid: str, severity: str, desc: str, raw: dict) -> RawFinding:
    return RawFinding(
        scanner="osint",
        scanner_template_id=tid,
        vulnerability_type=tid,  # canonical osint-* type resolves specific KB/CVSS
        target=domain,
        host=domain,
        severity=severity,
        description=desc,
        raw=raw,
    )