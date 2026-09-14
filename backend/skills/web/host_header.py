"""Host Header Injection — probe how the origin reacts to a spoofed Host /
X-Forwarded-Host header.

An application that trusts the Host header to build links can be abused in two
ways:

  1. General host-header injection — the attacker-controlled hostname is
     reflected into the page (e.g. into link/form action URLs), enabling
     cache poisoning / phishing against users.
  2. Password-reset poisoning — a reset page/flow that embeds the reflected
     host into its form action or reset link lets an attacker steal reset
     tokens (CRITICAL).

This skill sends `Host: evil.com` (and the `X-Forwarded-Host` variant) to the
base URL and a small set of password-reset/forgot endpoints. The authoritative
signal, mirroring the legacy `http_probe` detection, is the injected hostname
appearing in the response body OR in a redirect Location (pure status/body
diffing against a CDN tenant produces false positives and is ignored). A
reflection on a reset-context endpoint is rated CRITICAL ("reset flow"),
otherwise MEDIUM.

Context: `osint.host_header_reflection` records which endpoints reflected the
injected host. No external tools (httpx only).
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

INJECTED_HOST = "evil.com"
_INJECT_HEADERS = ("Host", "X-Forwarded-Host")

_RESET_PATHS = (
    "/forgot-password",
    "/password/forgot",
    "/password/reset",
    "/account/password/forgot",
    "/forgot",
    "/password/recovery",
)
_RESET_KEYWORDS = ("reset", "forgot")


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


def _targets(base: str) -> List[str]:
    root = base.rstrip("/")
    return [root] + [root + p for p in _RESET_PATHS]


def _reflection(body: str, final_host: str, injected: str = INJECTED_HOST
                ) -> Optional[str]:
    """Return 'body' or 'redirect' when the injected host is reflected.

    None means no authoritative reflection (definite non-finding).
    """
    if body and injected in body:
        return "body"
    if final_host and injected in final_host.lower():
        return "redirect"
    return None


def _send_get(client: httpx.Client, url: str,
              headers: dict) -> Optional[Tuple[List[int], str, str, str]]:
    """Return (statuses, body, final_host, location) or None on failure.

    `statuses` is the full response chain (redirect history + final) so
    callers can distinguish an authoritative 2xx/3xx page from a 404/5xx
    error page that merely echoes the injected Host header back.
    """
    try:
        resp = client.get(url, headers=headers, timeout=PROBE_TIMEOUT)
    except Exception:  # noqa: BLE001
        return None
    statuses = [h.status_code for h in getattr(resp, "history", [])]
    statuses.append(resp.status_code)
    body = resp.text or ""
    final_host = (urlparse(str(resp.url)).hostname or "").lower()
    location = (resp.headers.get("location") or "").lower()
    return statuses, body, final_host, location


def _path_exists(statuses: List[int]) -> bool:
    """True when the response chain contains a real (2xx/3xx) page.

    Apache and other servers echo the Host header into their error bodies,
    so a reflection observed on a 404/500/403 error page is NOT host-header
    injection — the path must actually exist to be authoritative.
    """
    return any(200 <= s < 400 for s in (statuses or []))


def _reset_context(path: str, body: str) -> bool:
    low_path = path.lower()
    if any(k in low_path for k in _RESET_KEYWORDS):
        return True
    low_body = body.lower()
    return "reset" in low_body and "password" in low_body


@register
class HostHeaderInjectSkill(Skill):
    """Detect Host header injection / password-reset poisoning."""

    name = "host-header-inject"
    display_name = "Host Header Injection"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["port_80_open", "port_443_open"]

    timeout_seconds = 60
    max_requests = 14

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"host_header_scan": "no-target"}})

        try:
            with _client() as client:
                baseline = client.get(base + "/", timeout=PROBE_TIMEOUT)
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"host_header_scan": "unreachable"}})
        if not (200 <= baseline.status_code < 400):
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"host_header_scan": "no-baseline"}})

        findings: list[RawFinding] = []
        reflected_endpoints: list[str] = []

        with _client() as client:
            for url in _targets(base):
                reports: list[dict] = []
                for header_name in _INJECT_HEADERS:
                    result = _send_get(client, url,
                                       {header_name: INJECTED_HOST})
                    if result is None:
                        continue
                    statuses, body, final_host, location = result
                    method = _reflection(body, final_host)
                    if method is None:
                        continue
                    # Authoritative gate: the injected host must be reflected
                    # by an EXISTING page (2xx/3xx). A 404/5xx error page that
                    # echoes the Host header is not injection — skip it so a
                    # nonexistent /forgot-password on stock servers is never
                    # reported (let alone rated Critical reset poisoning).
                    if not _path_exists(statuses):
                        continue
                    is_reset = _reset_context(url, body)
                    reports.append({
                        "header": header_name,
                        "method": method,
                        "status": statuses[-1],
                        "is_reset": is_reset,
                        "redirect_target": location if method == "redirect" else "",
                    })
                if not reports:
                    continue
                # Prefer the reset/stricter report for the endpoint.
                best = max(reports,
                           key=lambda r: (r["is_reset"],
                                          r["method"] == "body"))
                is_reset = best["is_reset"]
                severity = "critical" if is_reset else "medium"
                reflected_endpoints.append(url)
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="host-header-injection",
                    vulnerability_type="host_header_injection",
                    target=base, host=base,
                    severity=severity,
                    url=url,
                    description=(
                        f"Host header injection via {best['header']}: injected "
                        f"{INJECTED_HOST} reflected in {best['method']}"
                        + (" on password-reset context (reset-flow poisoning)"
                           if is_reset else "")
                        + f" at {url}"),
                    raw={
                        "injected_host": INJECTED_HOST,
                        "header": best["header"],
                        "reflection": best["method"],
                        "status": best["status"],
                        "target_path": url,
                        "is_reset_context": is_reset,
                        "redirect_target": best["redirect_target"],
                        "reports": reports,
                    },
                ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {
                    "host_header_reflection": False,
                    "host_header_scan": "clear"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "host_header_reflection": True,
                "host_header_endpoints": reflected_endpoints,
                "host_header_scan": "reflected"}})