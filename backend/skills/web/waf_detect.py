"""WAF / CDN Detection — identify a web application firewall or CDN provider
in front of the target origin.

Ports the legacy `waf_detect` scanner onto the Skill contract. Signals:

  1. Response-header fingerprints (cf-ray, x-sucuri-id, x-amz-cf-id, server
     values, …) for 25+ providers.
  2. A deliberate bad-request probe (URL-encoded XSS/SQLi in the path) whose
     block/error page is matched against per-provider signatures.
  3. Response-time spread across repeated requests (tight spread + CDN headers
     → edge caching).

When a provider is confirmed the skill records `waf_detected` / `waf_provider`
on the shared context (the origin-hunt skill keys off that to look for the real
IP behind the WAF) and emits a WAF_DETECTED INFO finding carrying waf_metadata.

Never raises: any failure degrades to no finding.
Tools: nothing external (httpx).
"""
from __future__ import annotations

from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from pipeline.scanner.waf_detect import (
    _HEADER_SIGNATURES,
    _PROVIDER_META,
    _PROVIDER_SERVER_MARKS,
    WafDetectScanner,
)
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 10
REPEAT_REQUESTS = 3

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

_BLOCK_KEYWORDS = WafDetectScanner._BLOCK_KEYWORDS

_BLOCK_PAGE_SIGS = {
    "cloudflare": ("cloudflare", "attention required", "cf-error-code",
                   "cf-ray", "error 1005", "error 1006", "error 1020"),
    "akamai": ("akamai", "access denied", "the request could not be completed",
               "akamaighost", "reference #"),
    "fastly": ("fastly", "fastly error", "vcl_error", "fetch failed",
               "error 503 first byte timeout"),
    "azure-cdn": ("azure", "azure front door", "request blocked by azure",
                  "403 forbidden (azure)"),
    "azure-frontdoor": ("azure front door", "front door"),
    "modsecurity": ("mod_security", "modsecurity", "mod_sec",
                    "error 403 forbidden by security policy"),
    "sucuri": ("sucuri.net", "blocked by sucuri", "sucuri web application firewall"),
    "imperva": ("incapsula", "incapsula incident id", "imperva"),
    "barracuda": ("barracuda", "blocked by barracuda", "access denied (barracuda)"),
    "f5-bigip": ("bigip", "asfvb", "request rejected by f5", "f5 networks"),
    "radware": ("radware", "appwall", "request blocked by appwall"),
    "stackpath": ("stackpath", "access denied by stackpath"),
    "citrix": ("netscaler", "citrix", "appfw"),
    "fortinet": ("fortiweb", "fortinet", "violation of site security policy"),
    "zscaler": ("zscaler", "blocked by zscaler", "zscaler security"),
    "generic-waf": ("access denied", "your request has been blocked",
                    "security check", "unusual traffic", "rejected by",
                    "web application firewall", "rate limit exceeded",
                    "you have been blocked"),
}

_CDN_PROVIDERS = {
    "cloudflare", "akamai", "aws-cloudfront", "aws-waf", "fastly",
    "azure-cdn", "azure-frontdoor", "vercel", "radware", "stackpath",
    "gcp-cloudarmor", "generic-cdn",
}

_PICK_ORDER = (
    "cloudflare", "akamai", "aws-cloudfront", "aws-waf", "azure-frontdoor",
    "azure-cdn", "vercel", "sucuri", "imperva", "fastly", "radware",
    "fortinet", "citrix", "zscaler", "barracuda", "f5-bigip", "reblaze",
    "wallarm", "ddos-guard", "pentasecurity", "watson", "gcp-cloudarmor",
    "modsecurity", "aws-shield", "generic-cdn",
)


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


def _header_detect(headers: dict) -> Tuple[set[str], set[str]]:
    low = {k.lower(): (v or "").strip() for k, v in headers.items()}
    providers: set[str] = set()
    methods: set[str] = set()

    for header, needle, provider in _HEADER_SIGNATURES:
        value = low.get(header)
        if value is None:
            continue
        if needle and needle.lower() not in value.lower():
            continue
        providers.add(provider)
        methods.add("header")

    for provider, marks in _PROVIDER_SERVER_MARKS.items():
        server_values = " ".join(
            low.get(h) or "" for h in ("server", "via", "x-powered-by"))
        if any(m in server_values.lower() for m in marks):
            providers.add(provider)
            methods.add("server-value")

    return providers, methods


def _bad_request_probe(client: httpx.Client, url: str) -> Tuple[str, int]:
    probe = (url.rstrip("/")
             + "/%3Cscript%3Ealert(1)%3C/script%3E?id=1'OR'1'='1")
    try:
        resp = client.get(probe, timeout=PROBE_TIMEOUT)
        return (resp.text or ""), resp.status_code
    except Exception:  # noqa: BLE001
        return "", 0


def _block_page_detect(body: str) -> set[str]:
    low = body.lower()
    found: set[str] = set()
    for provider, needles in _BLOCK_PAGE_SIGS.items():
        if any(n in low for n in needles):
            found.add(provider)
    if any(k in low for k in _BLOCK_KEYWORDS):
        found.add("generic-waf")
    return found


def _timing_spread(client: httpx.Client,
                   url: str) -> Tuple[Optional[float], Optional[float]]:
    from datetime import datetime
    timings: list[float] = []
    try:
        for _ in range(REPEAT_REQUESTS):
            t0 = datetime.now()
            client.get(url, timeout=PROBE_TIMEOUT)
            timings.append((datetime.now() - t0).total_seconds() * 1000.0)
    except Exception:  # noqa: BLE001
        return None, None
    if not timings:
        return None, None
    timings.sort()
    return (round(timings[len(timings) // 2], 1),
            round(max(timings) - min(timings), 1))


def _pick_provider(providers: set[str]) -> str:
    for p in _PICK_ORDER:
        if p in providers:
            return p
    return "generic-waf"


def _confidence(signal_count: int, providers: set[str], bad_status: int,
                base_status: int) -> str:
    score = 0.0
    score += min(signal_count * 0.25, 0.6)
    if len(providers) >= 2:
        score += 0.15
    if bad_status and base_status and bad_status in (400, 403, 404, 429):
        score += 0.2
    if bad_status in (403, 429):
        score += 0.1
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


@register
class WafDetectSkill(Skill):
    """Detect a WAF/CDN in front of the target origin."""

    name = "waf-detect"
    display_name = "WAF Detection"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["port_80_open", "port_443_open"]

    timeout_seconds = 60
    max_requests = 10

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"waf_detect_skipped": True}})

        try:
            with _client() as client:
                base_resp = client.get(base + "/", timeout=PROBE_TIMEOUT)
                base_headers = dict(base_resp.headers)
                base_body = base_resp.text or ""
                base_status = base_resp.status_code
        except Exception:  # noqa: BLE001
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"waf_detect_unreachable": base}})

        providers, methods = _header_detect(base_headers)

        with _client() as client:
            bad_body, bad_status = _bad_request_probe(client, base)
            providers |= _block_page_detect(bad_body)
            median_ms, spread_ms = _timing_spread(client, base)

        has_cdn = any(p in providers for p in _CDN_PROVIDERS)
        if spread_ms is not None and spread_ms > 500 and has_cdn:
            providers.add("generic-cdn")
            methods.add("timing")

        if not providers:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {
                    "waf_detected": False, "waf_method": "clear"}})

        provider = _pick_provider(providers)
        confidence = _confidence(len(methods), providers, bad_status, base_status)

        meta = _PROVIDER_META.get(provider, {"vendor": "Unknown", "kind": "waf"})
        waf_metadata = {
            "provider": provider,
            "vendor": meta.get("vendor"),
            "kind": meta.get("kind"),
            "confidence": confidence,
            "method": "+".join(sorted(methods)) or "header",
            "detected_headers": sorted(providers),
            "block_page": bool(bad_body and bad_body != base_body),
        }

        finding = RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="waf-detected",
            vulnerability_type="reconnaissance",
            target=base, host=base,
            severity="info",
            url=base + "/",
            description=(f"WAF/CDN detected in front of origin: {provider} "
                         f"(confidence {confidence}, via {waf_metadata['method']})"),
            raw={
                "provider": provider,
                "confidence": confidence,
                "method": waf_metadata["method"],
                "waf_metadata": waf_metadata,
                "detected_headers": sorted(providers),
                "timing_spread_ms": spread_ms,
                "block_page": waf_metadata["block_page"],
            },
        )
        return SkillResult(
            skill_name=self.name, success=True, findings=[finding],
            context_updates={
                "osint": {"waf_metadata": waf_metadata},
                "waf_detected": True,
                "waf_provider": provider,
            })