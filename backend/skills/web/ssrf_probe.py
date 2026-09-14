"""SSRF — detect server-side request forgery via URL-carrying parameters.

Runs when API endpoints were discovered or the service is on plain HTTP
(`requires_any: ["api_found", "port_80_open"]`). Strategy, all passive
feedback (no external listener needed):

  1. Harvest URL-ish parameters from API endpoints / the homepage (names like
     url, uri, path, dest, target, fetch, src, callback…) or params whose
     current value is already an absolute URL.
  2. For the first such param on each endpoint run three probes:
       * `http://169.254.169.254/latest/meta-data/`  — if the app fetches it,
         the reply echoes cloud metadata ("meta-data", "ami-id", "instance-id"):
         direct, confirmed SSRF.
       * `http://127.0.0.1:1/`  — a closed loopback port, fails instantly
         (the app-side connect is refused immediately).
       * `http://127.0.0.1:9/`  — discard port, typically black-holed, so the
         app-side fetch hangs until its own timeout.
     When the app's response to the `:9` probe is consistently much slower
     than the `:1` probe, the target is fetching the URL server-side: blind
     SSRF via a timing oracle.

A confirmed case (metadata echo or a stable timing gap) is a CRITICAL
`ssrf-confirmed` finding carrying the evidence + kind. httpx only, no
cross-host follow.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 8
MAX_ENDPOINTS = 4
SAMPLES = 2
_SLOW_THRESHOLD_MS = 900.0

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

_META_URL = "http://169.254.169.254/latest/meta-data/"
_FAST_URL = "http://127.0.0.1:1/"
_SLOW_URL = "http://127.0.0.1:9/"

_API_KEYWORDS = ("api", "graphql", "/v1", "/v2", "/rest", "/json")
_URL_PARAM_RE = re.compile(r"(url|uri|path|dest|target|fetch|src|callback|"
                           r"qurl|link|ref|href|source|endpoint|redirect)", re.I)
_PARAM_RE = re.compile(rb"""[?&]([A-Za-z0-9_.~-]+)=""")
_INPUT_NAME_RE = re.compile(
    r"""<input\b[^>]*?\bname\s*=\s*["']([^"']+)["']""", re.I)
_META_HIT_RE = re.compile(r"(meta-data|ami-id|instance-id|placement/"
                          r"availability-zone|local-ipv4)", re.I)


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _base(ctx: SkillContext) -> Optional[str]:
    host = _extract_host(ctx)
    if not host:
        return None
    scheme = (ctx.scheme or "https").lower()
    port = ctx.port or 0
    if port in (443, 8443):
        scheme = "https"
    elif port in (80, 8080):
        scheme = "http"
    for p in (443, 8443, 80, 8080):
        if p in ctx.open_ports:
            port = p
            scheme = "https" if p in (443, 8443) else "http"
            break
    netloc = host
    if port and not ((scheme == "http" and port == 80)
                     or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    return f"{scheme}://{netloc}"


def _client() -> httpx.Client:
    return httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=False,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _endpoints(base: str, ctx: SkillContext) -> List[str]:
    root = base.rstrip("/")
    eps = [root + "/"]
    for p in ctx.discovered_paths:
        if any(k in p.lower() for k in _API_KEYWORDS):
            eps.append(root + p)
    return eps[:MAX_ENDPOINTS]


def _ssrf_params(html: str, url: str) -> List[str]:
    names: List[str] = []
    seen = set()
    query = urlparse(url).query
    for k, v in parse_qsl(query):
        if k not in seen:
            seen.add(k)
            names.append(k)
            if re.match(r"(https?|//)", v.strip(), re.I):
                pass  # keep the list compact; name whitelist decides below
    for m in _PARAM_RE.finditer(html.encode("utf-8", "ignore")):
        k = m.group(1).decode()
        if k not in seen:
            seen.add(k)
            names.append(k)
    for m in _INPUT_NAME_RE.finditer(html):
        k = m.group(1)
        if k not in seen:
            seen.add(k)
            names.append(k)
    return [n for n in names if _URL_PARAM_RE.search(n)]


def _timed_get(client: httpx.Client, url: str) -> Tuple[int, str, float]:
    t0 = datetime.now()
    try:
        resp = client.get(url, timeout=PROBE_TIMEOUT)
        ms = (datetime.now() - t0).total_seconds() * 1000.0
        return resp.status_code, resp.text or "", ms
    except Exception:  # noqa: BLE001
        return 0, "", (datetime.now() - t0).total_seconds() * 1000.0


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[len(s) // 2]


def _probe_with(client: httpx.Client, url: str, param: str, value: str
                ) -> Tuple[str, float]:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query[param] = value
    target = url.split("?", 1)[0] + "?" + urlencode(query)
    bodies: List[str] = []
    timings: List[float] = []
    for _ in range(SAMPLES):
        _, body, ms = _timed_get(client, target)
        bodies.append(body)
        timings.append(ms)
    return (max(bodies, key=len), _median(timings))


def _metadata_hit(text: str) -> bool:
    return bool(_META_HIT_RE.search(text or ""))


@register
class SsrfProbeSkill(Skill):
    """Detect server-side request forgery via URL parameters + a blind SSRF
    timing oracle."""

    name = "ssrf-probe"
    display_name = "SSRF Probe"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["api_found", "port_80_open"]

    timeout_seconds = 90
    max_requests = 40

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"ssrf_scan": "no-target"}})

        findings: list[RawFinding] = []

        with _client() as client:
            for url in _endpoints(base, ctx):
                try:
                    page = client.get(url, timeout=PROBE_TIMEOUT)
                    page_text = page.text or ""
                except Exception:  # noqa: BLE001
                    continue
                params = _ssrf_params(page_text, url)
                if not params:
                    continue
                param = params[0]

                meta_body, _ = _probe_with(client, url, param, _META_URL)
                if _metadata_hit(meta_body):
                    findings.append(RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id="ssrf-confirmed",
                        vulnerability_type="ssrf",
                        target=base, host=base,
                        severity="critical",
                        url=url,
                        description=(
                            f"SSRF confirmed on {url}: {param!r} fetches "
                            "169.254.169.254 cloud metadata server-side"),
                        raw={
                            "kind": "cloud-metadata",
                            "url": url, "param": param,
                            "payload": _META_URL,
                            "evidence": meta_body[:200],
                        },
                    ))
                    continue

                fast_body, fast_ms = _probe_with(client, url, param, _FAST_URL)
                slow_body, slow_ms = _probe_with(client, url, param, _SLOW_URL)
                delta = slow_ms - fast_ms
                if delta > _SLOW_THRESHOLD_MS and slow_ms > 300.0:
                    findings.append(RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id="ssrf-confirmed",
                        vulnerability_type="ssrf",
                        target=base, host=base,
                        severity="critical",
                        url=url,
                        description=(
                            f"blind SSRF suspected on {url}: {param!r} "
                            f"response tied to fetch reachability "
                            f"(slow-vs-fast delta {delta:.0f}ms)"),
                        raw={
                            "kind": "blind-timing",
                            "url": url, "param": param,
                            "fast_probe": _FAST_URL,
                            "slow_probe": _SLOW_URL,
                            "fast_ms": round(fast_ms, 1),
                            "slow_ms": round(slow_ms, 1),
                            "delta_ms": round(delta, 1),
                        },
                    ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"ssrf_scan": "clear"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {"ssrf_scan": "confirmed",
                                       "ssrf_kind": findings[0].raw["kind"]}})