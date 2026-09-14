"""CORS Misconfiguration — probe how the origin reflects cross-origin
Access-Control headers.

An API that reflects an attacker-supplied `Origin` (or that answers `null`,
or `*`) — while also allowing credentials — lets any site read the victim's
authenticated responses. Detection:

  * `Origin: https://evil.com` reflected exactly in `Access-Control-Allow-Origin`
    with `Access-Control-Allow-Credentials: true`  -> CRITICAL (auth-credential
    theft).
  * Same reflection without credentials                     -> MEDIUM.
  * `Origin: null` honoured                               -> MEDIUM (a sandboxed
    page can still make credentialed requests).
  * `Access-Control-Allow-Origin: *` with credentials      -> CRITICAL (invalid
    combo some servers still serve).

Probes the API endpoints already discovered (when the `api_found` condition
fired) plus the base page; with `requires_any: [api_found, port_443_open]`
it also runs standalone on TLS targets. Findings:
`cors-wildcard-credentials` (CRITICAL), `cors-reflected-credentials`
(CRITICAL), `cors-reflected-origin` (MEDIUM), `cors-null-origin` (MEDIUM).
httpx only.
"""
from __future__ import annotations

from typing import List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 10

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

EVIL_ORIGIN = "https://evil.com"
_NULL_ORIGIN = "null"
MAX_ENDPOINTS = 4

_API_KEYWORDS = ("api", "graphql", "/v1", "/v2", "/rest", "/json", "/data")


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
    return httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _endpoints(base: str, ctx: SkillContext) -> List[str]:
    root = base.rstrip("/")
    eps = [root + "/"]
    for p in ctx.discovered_paths:
        if any(k in p.lower() for k in _API_KEYWORDS):
            eps.append(root + p)
    return eps[:MAX_ENDPOINTS]


def _classify(acao: str, acac: str,
              origin: str) -> Optional[Tuple[str, str, str]]:
    """Return (template_id, severity, kind) for a response's CORS headers, or
    None when no misconfiguration is present."""
    acac_true = (acac or "").strip().lower() == "true"
    a = (acao or "").strip()

    if a == "*":
        return ("cors-wildcard-credentials", "critical",
                "wildcard+credentials") if acac_true else None

    if a.lower() == _NULL_ORIGIN:
        return ("cors-null-origin", "medium" if acac_true else "low",
                "null-origin")

    if a.lower() == origin.lower():
        if acac_true:
            return ("cors-reflected-credentials", "critical",
                    "reflected+credentials")
        return ("cors-reflected-origin", "medium", "reflected-origin")

    return None


@register
class CorsProbeSkill(Skill):
    """Detect CORS misconfigurations (origin reflection, null origin,
    wildcard+credentials)."""

    name = "cors-probe"
    display_name = "CORS Misconfiguration"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["api_found", "port_443_open"]

    timeout_seconds = 60
    max_requests = 10

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"cors_scan": "no-target"}})

        findings: list[RawFinding] = []
        probed: list[str] = []

        with _client() as client:
            for url in _endpoints(base, ctx):
                for origin in (EVIL_ORIGIN, _NULL_ORIGIN):
                    try:
                        resp = client.get(url, headers={"Origin": origin},
                                          timeout=PROBE_TIMEOUT)
                    except Exception:  # noqa: BLE001
                        continue
                    acao = resp.headers.get("access-control-allow-origin")
                    if not acao:
                        continue
                    acac = resp.headers.get("access-control-allow-credentials",
                                            "")
                    cls = _classify(acao, acac, origin)
                    if cls is None:
                        continue
                    template_id, severity, kind = cls
                    probed.append(url)
                    findings.append(RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id=template_id,
                        vulnerability_type="cors",
                        target=base, host=base,
                        severity=severity,
                        url=url,
description=(
                        f"CORS misconfiguration on {url}: "
                        f"ACAO={acao!r} ACAC={acac or '-'} ({kind})"),
                        raw={
                            "url": url,
                            "access_control_allow_origin": acao,
                            "access_control_allow_credentials": acac or "",
                            "kind": kind,
                            "probed_origin": origin,
                        },
                    ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"cors_scan": "clear"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "cors_scan": "misconfigured",
                "cors_affected_endpoints": list(dict.fromkeys(probed))}})