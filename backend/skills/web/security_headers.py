"""Security Headers Audit — check 8 key security headers on the target origin
and validate their values.

Issues an authenticated-free GET to {base}/ and evaluates the response
headers against the baseline set, including value-level checks:

  Strict-Transport-Security  (HSTS; HTTPS-only requirement)
  Content-Security-Policy    (CSP)
  X-Frame-Options            (XFO; skipped when CSP frame-ancestors exists)
  X-Content-Type-Options
  Referrer-Policy
  Permissions-Policy
  Cross-Origin-Opener-Policy
  Cross-Origin-Resource-Policy

Findings:
  - MISSING_SECURITY_HEADER (LOW) — one of the 8 absent from the response
  - CSP_UNSAFE_INLINE (MEDIUM)   — CSP present but allows 'unsafe-inline'/
    'unsafe-eval' / bare wildcards in script sources
  - SECURITY_HEADER_WEAK (LOW)   — header present but value is weak
    (e.g. HSTS max-age under one year)

Context:
  - osint.security_headers (per-header presence + notes)
Tools: nothing external (httpx).
"""
from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 10

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

_MIN_HSTS_MAX_AGE = 31_536_000  # 1 year

# name -> skip-if-missing note (HSTS only counts on HTTPS)
_REQUIRED_HEADERS = (
    ("strict-transport-security",
     "only meaningful on HTTPS (skipped on plain HTTP)"),
    ("content-security-policy", None),
    ("x-frame-options", "equivalent covered when CSP frame-ancestors present"),
    ("x-content-type-options", None),
    ("referrer-policy", None),
    ("permissions-policy", "fallback: feature-policy technology is legacy"),
    ("cross-origin-opener-policy", None),
    ("cross-origin-resource-policy", None),
)

_HSTS_MAX_AGE_RE = re.compile(r"(?i)max-age\s*=\s*(\d+)")
_CSP_UNSAFE_RE = re.compile(
    r"(?i)(script-src[^;]*['\"]unsafe-inline|default-src[^;]*['\"]unsafe-inline"
    r"|default-src[^;]*['\"]unsafe-eval|script-src[^;]*['\"]unsafe-eval"
    r"|script-src[^;]*\*)")
_CSP_FRAME_ANCESTORS_RE = re.compile(r"(?i)frame-ancestors\s+[^;]+")


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


def _hsts_max_age(value: str) -> Optional[int]:
    m = _HSTS_MAX_AGE_RE.search(value or "")
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _csp_unsafe_inline(csp_value: str) -> bool:
    """CSP allows script via inline/hazards beyond what a lock-down allows."""
    return bool(_CSP_UNSAFE_RE.search(csp_value or ""))


def _check_headers(headers: dict, is_https: bool) -> list[dict]:
    """Evaluate the 8 baseline headers; returns one dict per header.

    dict keys: header, present, reason (why flagged), skip.
    """
    low = {k.lower(): (v or "").strip() for k, v in headers.items()}
    results: list[dict] = []
    csp = low.get("content-security-policy")
    if csp and _CSP_FRAME_ANCESTORS_RE.search(csp):
        has_frame_ancestors = True
    else:
        has_frame_ancestors = False

    for header, skip_note in _REQUIRED_HEADERS:
        value = low.get(header)
        entry = {"header": header, "present": bool(value), "reason": None}
        if value:
            if header == "strict-transport-security":
                ma = _hsts_max_age(value)
                if ma is not None and ma < _MIN_HSTS_MAX_AGE:
                    entry["reason"] = (
                        f"HSTS max-age {ma} is below the recommended {_MIN_HSTS_MAX_AGE}")
            elif header == "content-security-policy":
                if _csp_unsafe_inline(value):
                    entry["reason"] = (
                        "CSP allows 'unsafe-inline'/'unsafe-eval'/wildcard script sources")
            elif header == "x-frame-options":
                if not re.search(r"(?i)^(?:\s*)(DENY|SAMEORIGIN)\b", value):
                    entry["reason"] = f"x-frame-options value is not DENY/SAMEORIGIN"
            elif header == "cross-origin-resource-policy" and \
                    not re.search(r"(?i)^(same-origin|same-site)\b", value):
                entry["reason"] = "cross-origin-resource-policy should be same-origin/same-site"
        else:
            if header == "strict-transport-security" and not is_https:
                entry["skip"] = skip_note
            elif header == "x-frame-options" and has_frame_ancestors:
                entry["skip"] = skip_note
            else:
                entry["reason"] = f"{header} header is missing"
        results.append(entry)
    return results


@register
class SecurityHeadersSkill(Skill):
    """Audit the origin's security headers and validate their values."""

    name = "security-headers"
    display_name = "Security Headers Audit"
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
                context_updates={"osint": {"security_headers_skipped": True}})

        findings: list[RawFinding] = []
        try:
            with _client() as client:
                resp = client.get(base + "/", timeout=PROBE_TIMEOUT)
                headers = dict(resp.headers)
        except Exception:  # noqa: BLE001 - unresponsive target
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"security_headers_unreachable": base}})

        is_https = base.lower().startswith("https://")
        report = _check_headers(headers, is_https)
        summary = {}
        for entry in report:
            summary[entry["header"]] = {
                "present": entry["present"],
                "reason": entry["reason"],
            }
            if entry.get("skip"):
                continue
            finding = None
            if not entry["present"]:
                finding = RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="missing-security-header",
                    vulnerability_type="misconfiguration",
                    target=base, host=base,
                    severity="low",
                    url=base + "/",
                    description=(f"{entry['header']} header is missing on {base}"),
                    raw={"header": entry["header"], "present": False},
                )
            elif entry["header"] == "content-security-policy" and entry["reason"]:
                finding = RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="csp-unsafe-inline",
                    vulnerability_type="misconfiguration",
                    target=base, host=base,
                    severity="medium",
                    url=base + "/",
                    description=f"{entry['reason']} on {base}",
                    raw={"header": "content-security-policy",
                         "csp": headers.get("Content-Security-Policy")},
                )
            elif entry["reason"]:
                finding = RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="security-header-weak",
                    vulnerability_type="misconfiguration",
                    target=base, host=base,
                    severity="low",
                    url=base + "/",
                    description=f"{entry['reason']} on {base}",
                    raw={"header": entry["header"],
                         "value": headers.get(entry["header"])},
                )
            if finding is not None:
                findings.append(finding)

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {"security_headers": summary}})