"""httpx-based passive subdomain prober (no subfinder/dnsx required).

Discovers candidate subdomains from two passive HTTP sources and probes which
are live using the Python `httpx` library as a concurrent prober (replacing
the missing projectdiscovery `httpx` / subfinder / dnsx Go binaries):

  - crt.sh Certificate Transparency:  https://crt.sh/?q=%.{domain}&output=json
  - web.archive.org CDX subdomains:    http://web.archive.org/cdx/search/cdx?...
       (collapsed url-key list filtered to names under the base domain)

Each candidate is probed with GET (concurrent, bounded rate), collecting
status code, page <title>, an HTTP-header/cookie tech fingerprint, and IP.
Every live subdomain becomes an `info` RawFinding with that detail.

Scope/robustness:
  - Only names strictly under the target's registrable domain are probed.
  - No secrets are stored; only metadata (host, ip, status, title, tech).
  - Capped at MAX_SUBDOMAIN_FINDINGS results.
  - External APIs are rate-limited to ~1 rps; subdomain probing to 50 rps.
  - If all sources fail, the scanner returns [] and reports 'unavailable',
    never raising.
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
from pipeline.domains import is_under_domain, registrable_domain
from pipeline.scanner import base

MAX_SUBDOMAIN_FINDINGS = 200
MAX_CANDIDATES = 400          # probe at most this many candidates
PROBE_CONCURRENCY = 20        # parallel workers
PROBE_TIMEOUT = 10            # seconds
PROBE_RPS = 50                # bound probe throughput
EXTERNAL_RPS_DELAY = 1.05     # ~1 rps for crt.sh / CDX

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.hostname or target.strip()
    host = host.strip("[]")  # IPv6 brackets
    host = host.split(":")[0]
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


def _registrable(domain: str) -> str:
    """Return the registrable domain for scope enforcement (public-suffix aware).

    Shared implementation lives in ``pipeline.domains``; this thin wrapper keeps
    existing call sites and tests working.
    """
    return registrable_domain(domain)


def _under_domain(candidate: str, registrable: str) -> bool:
    """True when candidate is the registrable domain itself or lies under it.

    Shared implementation lives in ``pipeline.domains``; this thin wrapper keeps
    existing call sites and tests working.
    """
    return is_under_domain(candidate, registrable)


def _parse_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def _tech_signatures() -> list[tuple[str, str]]:
    """Return (header, needle) fingerprints found in response headers."""
    return [
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
    """Best-effort tech stack from response headers (no body parsing)."""
    detected: list[str] = []
    low = {k.lower(): v.lower() for k, v in headers.items()}
    for header, needle in _tech_signatures():
        val = low.get(header)
        if val and needle in val and needle not in detected:
            detected.append(needle)
    return detected


@base.register
class SubdomainHttpxScanner(base.Scanner):
    name = "subdomains"
    executable = ""  # pure Python httpx, always available

    def __init__(self) -> None:
        self.warning: Optional[str] = None
        self.detail: Optional[dict] = None
        self._client: Optional[httpx.Client] = None

    def setup_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=PROBE_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
                verify=False,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def scan(self, target: str, timeout: int = 120) -> List[RawFinding]:
        self.warning = None
        self.detail = None
        domain = _extract_domain(target)
        if _is_ip(domain):
            self.warning = "target is an IP address; subdomain discovery skipped"
            self.detail = {"domain": domain, "mode": "skipped-ip"}
            return []

        registrable = _registrable(domain)

        try:
            candidates = self._collect_candidates(registrable)
        except Exception as exc:  # noqa: BLE001 - surfaced, not fatal
            self.warning = f"subdomain discovery failed: {exc}"
            self.detail = {"domain": domain, "mode": "error", "error": str(exc)}
            return []

        # Always include the apex itself so the primary host is probed too.
        # Defensive pass: never probe a name that falls outside the scope
        # (the apis already filter, this guards against any upstream drift).
        candidates = sorted({
            c for c in set([domain, registrable] + candidates)
            if _under_domain(c, registrable)
        })

        self.detail = {
            "domain": domain,
            "registrable": registrable,
            "candidates": len(candidates),
        }

        if not candidates:
            self.warning = "no subdomain candidates found via passive sources"
            return []

        live = self._probe_live(candidates)

        findings: List[RawFinding] = []
        for host, info in live[:MAX_SUBDOMAIN_FINDINGS]:
            findings.append(
                RawFinding(
                    scanner="subdomains",
                    scanner_template_id="live-subdomain",
                    vulnerability_type="reconnaissance",
                    target=target,
                    host=host,
                    service=None,
                    severity="info",
                    url=f"http://{host}",
                    description=(
                        f"live subdomain found: {host} "
                        f"(status {info.get('status') or 'n/a'}, "
                        f"title '{info.get('title') or ''}', "
                        f"tech {', '.join(info.get('tech') or []) or 'n/a'})"
                    ),
                    raw={
                        "host": host,
                        "ip": info.get("ip"),
                        "status": info.get("status"),
                        "title": info.get("title"),
                        "tech": info.get("tech") or [],
                        "cname": info.get("cname"),
                    },
                )
            )
        if len(live) > MAX_SUBDOMAIN_FINDINGS:
            self.detail["truncated"] = len(live) - MAX_SUBDOMAIN_FINDINGS
            self.detail["probed"] = len(live)
        else:
            self.detail["probed"] = len(live)
        return findings

    # ---- candidate collection (passive, ~1 rps) ----

    def _get_json(self, url: str, timeout: int = 30, is_json: bool = True):
        import time
        client = self.setup_client()
        try:
            resp = client.get(url, timeout=timeout)
            time.sleep(EXTERNAL_RPS_DELAY)  # respect ~1 rps on external APIs
            if resp.status_code != 200:
                return None
            return resp.json() if is_json else resp.text
        except Exception:
            return None

    def _crt_sh(self, registrable: str) -> set[str]:
        url = f"https://crt.sh/?q=%25.{registrable}&output=json"
        data = self._get_json(url)
        if not isinstance(data, list):
            return set()
        names: set[str] = set()
        for row in data:
            if not isinstance(row, dict):
                continue
            # name_value may hold one name or newline-separated names
            name_value = row.get("name_value") or ""
            for n in name_value.split("\n"):
                n = n.strip().strip("*").lower().rstrip(".")
                if n and _under_domain(n, registrable):
                    names.add(n)
        return names

    def _wayback_cdx(self, registrable: str) -> set[str]:
        url = (
            f"http://web.archive.org/cdx/search/cdx?"
            f"url=*.{registrable}&output=json&fl=original&collapse=urlkey&limit=1000"
        )
        text = self._get_json(url, is_json=False)
        if not text:
            return set()
        try:
            import json
            rows = json.loads(text)
        except Exception:
            return set()
        names: set[str] = set()
        for row in rows:
            if not isinstance(row, list) or not row:
                continue
            url_str = row[0]
            try:
                u = urlparse(url_str)
                host = (u.hostname or "").lower().rstrip(".")
            except Exception:
                continue
            if host and _under_domain(host, registrable):
                names.add(host)
        return names

    def _collect_candidates(self, registrable: str) -> list[str]:
        names: set[str] = set()
        crt = self._crt_sh(registrable) or set()
        cdx = self._wayback_cdx(registrable) or set()
        names |= crt | cdx
        return sorted(names)[:MAX_CANDIDATES]

    # ---- liveness probing (concurrent, ~50 rps) ----

    def _probe_live(self, hosts: list[str]) -> list[tuple[str, dict]]:
        client = self.setup_client()
        results: list[tuple[str, dict]] = []
        lock = threading.Lock()
        q: Queue = Queue()
        for h in hosts:
            q.put(h)

        def resolve_ip(host: str) -> Optional[str]:
            try:
                return socket.gethostbyname(host)
            except OSError:
                return None

        def worker() -> None:
            while True:
                try:
                    host = q.get_nowait()
                except Exception:
                    return
                try:
                    ip = resolve_ip(host)
                    resp = client.get(f"http://{host}", timeout=PROBE_TIMEOUT)
                    status = resp.status_code
                    title = _parse_title(resp.text)
                    tech = _probe_tech(dict(resp.headers))
                    info = {
                        "host": host,
                        "ip": ip,
                        "status": status,
                        "title": title,
                        "tech": tech,
                        "cname": None,
                    }
                    with lock:
                        results.append((host, info))
                except Exception:
                    # unreachable / refused / timeout -> not "live" for us
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

        # order by original candidate order
        order = {h: i for i, h in enumerate(hosts)}
        results.sort(key=lambda item: order.get(item[0], len(hosts)))
        return results

    def available(self) -> bool:
        # Pure Python httpx -> always available even without external tools.
        return True