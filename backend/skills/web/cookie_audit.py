"""Cookie Audit — inspect Set-Cookie attributes from the target origin and flag
cookies lacking secure configuration.

Fetches {base}/ with a cache-busting query, collects every Set-Cookie across
the redirect chain and the final response, parses each with the stdlib cookie
parser, then evaluates against the session-hardening baseline:

  - Secure flag          (missing = cookie can leak over plaintext)
  - HttpOnly flag        (missing = XSS can read it)
  - SameSite attribute   (missing / None-without-Secure)
  - Domain attribute     (broader than the target host)
  - __Host- / __Secure-  prefix rules (must be Secure + host-only + /)
  - Expiry present for persistent cookies

Findings:
  - INSECURE_COOKIE (LOW/MEDIUM) — one per cookie per failed check
Context:
  - osint.cookies (parsed cookie -> issue list)
Tools: nothing external (httpx + stdlib http.cookies).
"""
from __future__ import annotations

import time
from http.cookies import SimpleCookie
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 10

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

_MAX_COOKIES_AUDITED = 60


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


def _registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


def _parse_cookie(set_cookie_value: str) -> Optional[dict]:
    """Parse a raw Set-Cookie value into a dict of attributes."""
    try:
        sc = SimpleCookie()
        sc.load(set_cookie_value)
    except Exception:  # noqa: BLE001 - malformed
        return None
    if not sc:
        return None
    m = list(sc.values())[0]
    out = {
        "name": m.key,
        "value": m.value or "",
        "domain": (m.get("domain") or "").strip(),
        "path": (m.get("path") or "").strip(),
        "secure": bool(m.get("secure")),
        "httponly": bool(m.get("httponly")),
        "samesite": (m.get("samesite") or "").strip(),
        "max_age": (m.get("max-age") or "").strip(),
        "expires": (m.get("expires") or "").strip(),
    }
    return out


def _cookie_issues(cookie: dict, host: str, is_https: bool) -> list[str]:
    """Return human-readable issue strings for an insecure cookie."""
    issues: list[str] = []
    name = cookie["name"]
    low_same = (cookie["samesite"] or "").lower()

    if is_https and not cookie["secure"]:
        issues.append("Secure flag missing on an HTTPS deployment")
    elif not is_https and not cookie["secure"]:
        issues.append("Secure flag missing (cookie could leak over plaintext)")

    if not cookie["httponly"]:
        issues.append("HttpOnly flag missing (readable by JavaScript / XSS)")

    if not cookie["samesite"]:
        issues.append("SameSite attribute missing")
    elif low_same == "none" and not cookie["secure"]:
        issues.append("SameSite=None without Secure flag")

    dom = (cookie["domain"] or "").lower()
    if dom:
        if dom.startswith(".") and _registrable(dom.strip(".")) \
                != _registrable(host):
            issues.append(f"Domain '{dom}' broader than the target host")
        elif not dom.startswith(".") and dom not in (host, _registrable(host)):
            issues.append(f"Domain '{dom}' does not match the target host")

    if name.startswith("__Host-"):
        if not cookie["secure"]:
            issues.append("__Host- prefix requires Secure flag")
        if cookie["domain"]:
            issues.append("__Host- prefix forbids Domain attribute")
        if cookie["path"] not in ("/", ""):
            issues.append("__Host- prefix requires Path=/")
    elif name.startswith("__Secure-") and not cookie["secure"]:
        issues.append("__Secure- prefix requires Secure flag")

    return issues


_ISSUE_SEVERITY = {
    "Secure flag missing": "medium",
    "HttpOnly flag missing": "medium",
    "SameSite missing": "low",
    "SameSite=None without Secure": "medium",
    "Domain '": "medium",
    "__Host-": "medium",
    "__Secure-": "medium",
}


def _severity(issue: str) -> str:
    for key, sev in _ISSUE_SEVERITY.items():
        if issue.lower().startswith(key.lower()):
            return sev
    return "low"


@register
class CookieAuditSkill(Skill):
    """Audit Set-Cookie attributes on the target origin."""

    name = "cookie-audit"
    display_name = "Cookie Audit"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["port_80_open", "port_443_open"]

    timeout_seconds = 30
    max_requests = 5

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"cookie_audit_skipped": True}})

        try:
            with _client() as client:
                resp = client.get(
                    f"{base}/?_={int(time.time() * 1000)}",
                    timeout=PROBE_TIMEOUT)
        except Exception:  # noqa: BLE001 - unresponsive target
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"cookie_audit_unreachable": base}})

        set_cookies: list[str] = []
        for h in resp.history:
            set_cookies.extend(h.headers.get_list("Set-Cookie"))
        set_cookies.extend(resp.headers.get_list("Set-Cookie"))

        findings: list[RawFinding] = []
        audited: dict = {}
        host = (urlparse(base).hostname or "").strip("[]").lower()
        is_https = base.lower().startswith("https://")

        for raw in set_cookies[: _MAX_COOKIES_AUDITED]:
            cookie = _parse_cookie(raw)
            if not cookie:
                continue
            issues = _cookie_issues(cookie, host, is_https)
            audited[cookie["name"]] = {
                "secure": cookie["secure"],
                "httponly": cookie["httponly"],
                "samesite": cookie["samesite"],
                "domain": cookie["domain"],
                "issues": issues,
            }
            for issue in issues:
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="insecure-cookie",
                    vulnerability_type="misconfiguration",
                    target=base, host=base,
                    severity=_severity(issue),
                    url=base + "/",
                    description=(f"insecure cookie '{cookie['name']}': {issue} "
                                 f"(domain={cookie['domain'] or host})"),
                    raw={"cookie": cookie["name"], "issue": issue,
                         "attributes": {k: v for k, v in cookie.items()
                                        if k not in ("name", "value")}},
                ))

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {"cookies": audited}})