"""Subdomain Enumeration — crt.sh + Wayback candidates probed for liveness.

The old subdomain logic lived in the `subdomains` scanner; this skill replaces
it with the same passive-enumeration + concurrent httpx probing approach but
speaks the Skill contract: it collects candidate names from certificate
transparency (crt.sh) and the Wayback CDX archive, probes each with a bounded
concurrent HTTP GET, and only treats responding hosts as live.

Live subdomains are surfaced as INFO findings and merged into the shared
`subdomains` context so downstream skills (takeover checks, content discovery,
port scans) can target them.

Scope/robustness:
  - Only names strictly under the target's registrable domain are probed.
  - External APIs rate-limited to ~1 rps; probing bounded at ~50 rps.
  - Any source failure degrades to an empty candidate set, never raises.

Findings:
  - LIVE_SUBDOMAIN (INFO) — responding subdomain with status/title/tech
Context:
  - subdomains (live subdomains only)
Tools: nothing external (uses httpx + DNS via stdlib)
"""
from __future__ import annotations

import re
import socket
import threading
from queue import Queue
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

MAX_CANDIDATES = 400
PROBE_CONCURRENCY = 20
PROBE_TIMEOUT = 10
EXTERNAL_RPS_DELAY = 1.05

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")


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


def _registrable(domain: str) -> str:
    """Registrable domain for scope enforcement (public-suffix aware).

    Thin wrapper around the shared implementation in ``pipeline.domains``.
    """
    from pipeline.domains import registrable_domain
    return registrable_domain(domain)


def _under_domain(candidate: str, registrable: str) -> bool:
    """True when candidate is the registrable domain itself or lies under it.

    Thin wrapper around the shared implementation in ``pipeline.domains``.
    """
    from pipeline.domains import is_under_domain
    return is_under_domain(candidate, registrable)


def _client() -> httpx.Client:
    return httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _cert_names(registrable: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{registrable}&output=json"
    try:
        with _client() as c:
            import time
            resp = c.get(url, timeout=30)
            time.sleep(EXTERNAL_RPS_DELAY)
            data = resp.json() if resp.status_code == 200 else None
    except Exception:  # noqa: BLE001 - source failure degrades quietly
        return set()
    if not isinstance(data, list):
        return set()
    names: set[str] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        for n in (row.get("name_value") or "").split("\n"):
            n = n.strip().strip("*").lower().rstrip(".")
            if n and _under_domain(n, registrable):
                names.add(n)
    return names


def _wayback_names(registrable: str) -> set[str]:
    url = (
        "http://web.archive.org/cdx/search/cdx?"
        f"url=*.{registrable}&output=json&fl=original&collapse=urlkey&limit=1000"
    )
    try:
        import json
        with _client() as c:
            import time
            resp = c.get(url, timeout=30)
            time.sleep(EXTERNAL_RPS_DELAY)
            text = resp.text or "" if resp.status_code == 200 else ""
    except Exception:  # noqa: BLE001
        return set()
    try:
        rows = json.loads(text)
    except Exception:
        return set()
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, list) or not row:
            continue
        try:
            host = (urlparse(str(row[0])).hostname or "").lower().rstrip(".")
        except Exception:
            continue
        if host and _under_domain(host, registrable):
            names.add(host)
    return names


def _parse_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


_TECH_SIGNATURES = [
    ("server", "nginx"), ("server", "apache"), ("server", "iis"),
    ("server", "cloudflare"), ("server", "uvicorn"), ("server", "gunicorn"),
    ("server", "werkzeug"), ("server", "phusion"), ("x-powered-by", "php"),
    ("x-powered-by", "asp.net"), ("x-powered-by", "express"),
    ("x-powered-by", "django"), ("x-powered-by", "node"),
    ("x-powered-by", "java"), ("x-aspnet-version", "asp.net"),
    ("x-csrf-token", "csrf"), ("set-cookie", "phpsessid"),
    ("set-cookie", "jsessionid"), ("set-cookie", "uniquevisitorid"),
]


def _probe_tech(headers: dict) -> list[str]:
    detected: list[str] = []
    low = {k.lower(): v.lower() for k, v in headers.items()}
    for header, needle in _TECH_SIGNATURES:
        val = low.get(header)
        if val and needle in val and needle not in detected:
            detected.append(needle)
    return detected


def _collect_candidates(registrable: str) -> list[str]:
    names: set[str] = set()
    names |= _cert_names(registrable)
    names |= _wayback_names(registrable)
    return sorted(names)[:MAX_CANDIDATES]


def _probe_live(hosts: list[str]) -> list[tuple[str, dict]]:
    if not hosts:
        return []
    with _client() as client:
        results: list[tuple[str, dict]] = []
        lock = threading.Lock()
        q: Queue = Queue()
        for h in hosts:
            q.put(h)

        def worker() -> None:
            while True:
                try:
                    host = q.get_nowait()
                except Exception:
                    return
                try:
                    ip = None
                    try:
                        ip = socket.gethostbyname(host)
                    except OSError:
                        pass
                    resp = client.get(f"http://{host}", timeout=PROBE_TIMEOUT)
                    info = {
                        "ip": ip,
                        "status": resp.status_code,
                        "title": _parse_title(resp.text),
                        "tech": _probe_tech(dict(resp.headers)),
                    }
                    with lock:
                        results.append((host, info))
                except Exception:  # noqa: BLE001 - unreachable/refused/timeout
                    pass
                finally:
                    q.task_done()

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(PROBE_CONCURRENCY, len(hosts)))]
        for t in threads:
            t.start()
        q.join()
        for t in threads:
            t.join()

    order = {h: i for i, h in enumerate(hosts)}
    results.sort(key=lambda item: order.get(item[0], len(hosts)))
    return results


@register
class SubdomainEnumSkill(Skill):
    """Enumerate and probe subdomains from crt.sh + Wayback (live only)."""

    name = "subdomain-enum"
    display_name = "Subdomain Enumeration (Live)"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 120
    max_requests = 400

    def should_run(self, ctx: SkillContext) -> bool:
        if not _extract_host(ctx):
            return False
        return not _is_ip(_extract_host(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        findings: list[RawFinding] = []
        osint_add = {}

        if not host or _is_ip(host):
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"subdomain_enum_skipped": True}})

        registrable = _registrable(host)
        candidates = sorted(set([host, registrable] +
                                _collect_candidates(registrable)))
        osint_add["subdomain_candidates"] = candidates[:400]

        live = _probe_live(candidates)
        osint_add["subdomain_count"] = len(live)

        known = set(ctx.subdomains)
        live_hosts: list[str] = []
        for hostname, info in live:
            findings.append(self._live_finding(host, hostname, info))
            live_hosts.append(hostname)

        new_subs = [h for h in live_hosts if h not in known]
        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint_add, "subdomains": new_subs})

    def _live_finding(self, host: str, hostname: str,
                      info: dict) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="live-subdomain",
            vulnerability_type="reconnaissance",
            target=host, host=hostname,
            severity="info",
            url=f"http://{hostname}",
            description=(
                f"live subdomain found: {hostname} "
                f"(status {info.get('status') or 'n/a'}, "
                f"title '{info.get('title') or ''}', "
                f"tech {', '.join(info.get('tech') or []) or 'n/a'})"
            ),
            raw={
                "host": hostname,
                "ip": info.get("ip"),
                "status": info.get("status"),
                "title": info.get("title"),
                "tech": info.get("tech") or [],
            },
        )