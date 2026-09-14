"""Open Redirect — find redirect endpoints that forward to an attacker-chosen
destination.

Runs unconditionally (`requires_all: []`). Approach:

  1. Harvest URL-carrying query parameters from the target URL, discovered
     paths and the homepage HTML (param names that look like redirect/return/
     next/goto/url/target/…).
  2. For each (endpoint, param) pair shoot three payloads:
       * `//evil.com`      — protocol-relative forward
       * `https://evil.com/` — absolute URL forward
       * `javascript:alert(1)` — javascript: scheme mishandling
  3. Using no-follow requests, a `Location` header that carries the injected
     host (`evil.com`) or starts with `javascript:` confirms the redirect.

Payloads are sent with `allow_redirects=False` so the actual `Location` value
is observed. A confirmed redirect is a MEDIUM `open-redirect` finding; the
javascript variant is flagged in the same finding. httpx only (never makes a
cross-host follow request).
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 8
MAX_ENDPOINTS = 3
MAX_PARAMS = 8

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

PAYLOADS = ("//evil.com", "https://evil.com/", "javascript:alert(1)")

_INJECTED = "evil.com"
_REDIRECT_HINT_RE = re.compile(
    r"(redirect|return|next|goto|target|dest|callback|continue|rurl|"
    r"url|ref|ret|path|link|uri)", re.I)
_PARAM_RE = re.compile(rb"""[?&]([A-Za-z0-9_.~-]+)=""")
_INPUT_NAME_RE = re.compile(
    r"""<input\b[^>]*?\bname\s*=\s*["']([^"']+)["']""", re.I)


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


def _endpoints(base: str, ctx: SkillContext) -> List[str]:
    eps: List[str] = []
    root = base.rstrip("/")
    eps.append(root + "/")
    base_query = urlparse(ctx.target_url).query
    if base_query:
        eps.append(root + "/?" + base_query)
    for p in ctx.discovered_paths[:MAX_ENDPOINTS - 2]:
        if not p.startswith(("http://", "https://", "//")):
            eps.append(root + p)
    return eps[:MAX_ENDPOINTS]


def _candidate_params(html: str, url: str) -> List[str]:
    names: List[str] = []
    seen = set()
    query = urlparse(url).query
    for k, _ in parse_qsl(query):
        if k not in seen:
            seen.add(k)
            names.append(k)
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
    candidates = [n for n in names if _REDIRECT_HINT_RE.search(n)]
    return candidates[:MAX_PARAMS]


def _confirms(payload: str, location: str, body: str) -> bool:
    loc = (location or "").lower()
    if payload.startswith("javascript:"):
        return loc.startswith("javascript:")
    return _INJECTED in loc or _INJECTED in (body or "").lower()


def _client() -> httpx.Client:
    return httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=False,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _probe(client: httpx.Client, url: str, param: str, payload: str
           ) -> Tuple[int, str, str]:
    """Send the param with the payload; return (status, location, body)."""
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query[param] = payload
    target = url.split("?", 1)[0] + "?" + urlencode(query)
    try:
        resp = client.get(target, timeout=PROBE_TIMEOUT)
    except Exception:  # noqa: BLE001
        return 0, "", ""
    return resp.status_code, resp.headers.get("location", "") or "", resp.text or ""


@register
class OpenRedirectSkill(Skill):
    """Detect open redirects via URL-carrying query parameters."""

    name = "open-redirect"
    display_name = "Open Redirect"
    category = SkillCategory.WEB
    version = "1.0"

    requires_all: list[str] = []

    timeout_seconds = 60
    max_requests = 24

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"open_redirect_scan": "no-target"}})

        findings: list[RawFinding] = []

        with _client() as client:
            for url in _endpoints(base, ctx):
                try:
                    page = client.get(url, timeout=PROBE_TIMEOUT).text or ""
                except Exception:  # noqa: BLE001
                    continue
                params = _candidate_params(page, url)
                confirmed: List[dict] = []
                for param in params:
                    for payload in PAYLOADS:
                        status, location, body = _probe(client, url, param,
                                                        payload)
                        if not location and not body:
                            continue
                        if _confirms(payload, location, body):
                            confirmed.append({
                                "param": param,
                                "payload": payload,
                                "status": status,
                                "location": location,
                                "reflected_in_body": bool(body and _INJECTED
                                                           in body.lower()),
                            })
                            break  # one confirmed payload per param is enough
                if not confirmed:
                    continue
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="open-redirect",
                    vulnerability_type="open_redirect",
                    target=base, host=base,
                    severity="medium",
                    url=url,
                    description=(
                        f"open redirect on {url}: "
                        + "; ".join(
                            f"?{c['param']}={c['payload']} -> "
                            f"{c['location'][:60] or '(body echo)'}"
                            for c in confirmed)),
                    raw={
                        "target": url,
                        "confirmed": confirmed,
                        "params_tested": params,
                    },
                ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"open_redirect_scan": "clear"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {"open_redirect_scan": "redirect-found"}})