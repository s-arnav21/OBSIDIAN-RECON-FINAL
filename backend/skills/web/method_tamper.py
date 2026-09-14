"""HTTP Method / Override Confusion — detect when changing the HTTP method or
injecting override headers changes the server's behavior for the same resource.

Ports the legacy `http_probe` variant-diff logic onto the Skill contract and
focuses on the method side of it:

  1. HEAD vs GET      — a HEAD mirroring a different status/location than the
                        GET response (e.g. HEAD 200 where GET 403) is an
                        auth/access inconsistency.
  2. Override headers — `X-HTTP-Method-Override: GET` / `X-Method-Override`
                        on a POST, forcing the ORM/proxy/framework to treat
                        the request as another verb.
  3. Path override    — `X-Original-URL: /admin` / `X-Rewrite-URL: /admin`
                        rewriting the request path server-side (a common
                        Apache/nginx auth-bypass vector).

Each variant is diffed against a GET baseline. Only a *significant* change is
reported (an access flip 401/403→200, a status change, or a real body
difference) — identical responses are ignored, keeping CDN noise out.

Severity is LOW for behavioral differences and HIGH when the differing variant
body leaks sensitive keywords, or when the variant flips an auth guard to 200
(auth bypass). Findings use the `method-confusion` template (severity LOW/HIGH).

Nothing external; httpx only, `allow_redirects=False` so mirrors reflect true
origin behavior.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 10
_BODY_CAP = 5000
_EXCERPT_LIMIT = 500

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

# Verbose keyword set carried over from the legacy http_probe detector.
_SENSITIVE_LEAK_RE = re.compile(
    r"(password|passwd|token|key|secret|auth|credential|apikey|api[_-]?key)",
    re.I,
)

# (name, method, headers) — variants run against the baseline target.
_VARIANTS = (
    ("head", "HEAD", {}),
    ("x-http-method-override", "POST", {"X-HTTP-Method-Override": "GET"}),
    ("x-method-override", "POST", {"X-Method-Override": "GET"}),
    ("x-original-url-override", "GET", {"X-Original-URL": "/admin"}),
    ("x-rewrite-url-override", "GET", {"X-Rewrite-URL": "/admin"}),
)

_IDENTICAL = ("identical", "none")


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


def _targets(base: str, ctx: SkillContext) -> List[str]:
    paths = [base.rstrip("/") + "/"]
    for p in ctx.discovered_paths:
        if any(k in p.lower() for k in ("admin", "login", "panel", "/auth")):
            paths.append(base.rstrip("/") + p)
            break
    return paths


def _fetch(client: httpx.Client, url: str, method: str,
           headers: dict) -> Optional[dict]:
    bodyless = method == "HEAD"
    try:
        resp = client.request(method, url, headers=headers, timeout=PROBE_TIMEOUT)
    except Exception:  # noqa: BLE001
        return None
    text = "" if bodyless else (resp.text or "")
    return {
        "status": resp.status_code,
        "length": len(resp.content or b"") if not bodyless else 0,
        "body": text[:_BODY_CAP],
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "location": resp.headers.get("location"),
        "bodyless": bodyless,
    }


def _access_flip(base_status: int, variant_status: int) -> Optional[str]:
    unauthorized = {401, 403}
    if variant_status == 200 and base_status in unauthorized:
        return "auth-bypass"
    if base_status == 200 and variant_status in unauthorized:
        return "denied-on-variant"
    return None


def _diff_excerpt(base_body: str, var_body: str, limit: int = _EXCERPT_LIMIT
                  ) -> str:
    differing = var_body if len(var_body) >= len(base_body) else base_body
    if not differing:
        return ""
    return re.sub(r"\s+", " ", differing).strip()[:limit]


def _diff(base: dict, variant: dict) -> Optional[dict]:
    """Diff a variant against the baseline; None when its response was
    unpredictable or indistinguishable from the baseline."""
    if not variant or not base:
        return None
    status_changed = base["status"] != variant["status"]
    length_delta = abs(variant["length"] - base["length"])
    body_similar = variant["body"] == base["body"]
    location_changed = base.get("location") != variant.get("location")
    access_flip = _access_flip(base["status"], variant["status"])
    variant_body = variant.get("body") or ""

    if access_flip:
        return {
            "significant": True, "signal": access_flip,
            "base_status": base["status"], "variant_status": variant["status"],
            "length_delta": length_delta, "location_changed": location_changed,
            "reasoning": f"status {base['status']} -> {variant['status']}",
            "diff_excerpt": _diff_excerpt(base["body"], variant_body),
            "variant_body": variant_body,
        }
    if status_changed:
        return {
            "significant": True, "signal": "status-diff",
            "base_status": base["status"], "variant_status": variant["status"],
            "length_delta": length_delta, "location_changed": location_changed,
            "reasoning": f"status {base['status']} -> {variant['status']}",
            "diff_excerpt": _diff_excerpt(base["body"], variant_body),
            "variant_body": variant_body,
        }
    if variant["bodyless"]:
        # HEAD has no body by design — a bare body-size delta is meaningless.
        if location_changed:
            return {
                "significant": True, "signal": "location-diff",
                "base_status": base["status"], "variant_status": variant["status"],
                "length_delta": length_delta, "location_changed": True,
                "reasoning": "redirect target differs from GET",
                "diff_excerpt": _diff_excerpt(base["body"], variant_body),
                "variant_body": variant_body,
            }
        return None
    if length_delta > max(50, int(base["length"] * 0.1)) and not body_similar:
        return {
            "significant": True, "signal": "body-diff",
            "base_status": base["status"], "variant_status": variant["status"],
            "length_delta": length_delta, "location_changed": location_changed,
            "reasoning": f"body length changed by {length_delta} bytes",
            "diff_excerpt": _diff_excerpt(base["body"], variant_body),
            "variant_body": variant_body,
        }
    return None


def _sensitive_leak(text: str) -> list[str]:
    if not text:
        return []
    return sorted({m.group(0).lower()
                   for m in _SENSITIVE_LEAK_RE.finditer(text)})


def _severity(signal: str, variant_body: str) -> Tuple[str, list[str]]:
    if signal == "auth-bypass":
        return "high", []
    leaks = _sensitive_leak(variant_body)
    if leaks:
        return "high", leaks
    return "low", []


@register
class MethodTamperSkill(Skill):
    """Detect HTTP method / override confusion (HEAD, override headers, path
    override) that changes server behavior for the same resource."""

    name = "method-tamper"
    display_name = "HTTP Method Confusion"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["port_80_open", "port_443_open"]

    timeout_seconds = 60
    max_requests = 12

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"method_tamper_scan": "no-target"}})

        findings: list[RawFinding] = []
        for target in _targets(base, ctx):
            try:
                with _client() as client:
                    baseline = _fetch(client, target, "GET", {})
                    for name, method, headers in _VARIANTS:
                        if baseline is None:
                            break
                        variant = _fetch(client, target, method, headers)
                        diff = _diff(baseline, variant)
                        if not diff or not diff["significant"]:
                            continue
                        severity, leaks = _severity(diff["signal"],
                                                    diff["variant_body"])
                        kw = {"leak_keywords": leaks,
                              "data_leakage_suspected": True} if leaks else {}
                        findings.append(RawFinding(
                            scanner="skill:" + self.name,
                            scanner_template_id="method-confusion",
                            vulnerability_type="http_variant_diff",
                            target=base, host=base,
                            severity=severity,
                            url=target,
                            description=(
                                f"{name}: response differs from baseline "
                                f"({diff['reasoning']})"
                                + (f"; possible data leak — keywords: "
                                   f"{', '.join(leaks)}" if leaks else "")),
                            raw={
                                "variant": name,
                                "method": method,
                                "headers": headers,
                                "signal": diff["signal"],
                                "base_status": diff["base_status"],
                                "variant_status": diff["variant_status"],
                                "length_delta": diff["length_delta"],
                                "location_changed": diff["location_changed"],
                                "reasoning": diff["reasoning"],
                                "diff_excerpt": diff["diff_excerpt"],
                                **kw,
                            },
                        ))
            except Exception:  # noqa: BLE001
                continue

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {
                    "method_confusion_detected": False,
                    "method_tamper_scan": "clear"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "method_confusion_detected": True,
                "method_tamper_variants": {
                    f.raw["variant"] for f in findings},
                "method_tamper_scan": "confusion"}})