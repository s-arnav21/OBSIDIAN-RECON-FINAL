"""Spring Boot Actuator — probe a Spring application for exposed actuator
endpoints.

Gated on `tech_spring`. Spring Boot 1.x exposed all actuator endpoints
unauthenticated by default (a massive information leak); 2.x secured most but
/heapdump and /env have historically been left open on misconfigured apps.

Probe set (case variations covered by testing both /actuator prefix layouts):

  1. /actuator                  — the 2.x base listing (200 + JSON body).
  2. /actuator/env              — environment properties, often including
                                  datasource passwords, AWS keys, tokens.
  3. /actuator/heapdump         — full JVM heap binary (CRITICAL: secrets and
                                  in-memory credentials are extractable).
  4. /actuator/threaddump       — thread/lock state (intel).
  5. /actuator/httptrace        — recent HTTP requests incl. query strings.
  6. /actuator/configprops      — app config + often secrets.
  7. /actuator/mappings         — route map.
  8. Legacy 1.x paths (/env, /heapdump, /trace, /beans) on un-prefixed
     Spring Boot 1.x apps.

Severity: heapdump/env/configprops reading as data is CRITICAL; the rest are
MEDIUM (informational endpoints). Findings: `actuator-heapdump` (CRITICAL),
`actuator-env-exposed` (CRITICAL), `actuator-exposed` (MEDIUM),
`actuator-legacy-exposed` (MEDIUM). httpx only.
"""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 8

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

# (path, template_id, severity, kind)
_ACTUATOR_PROBES = (
    ("/actuator", "actuator-exposed", "medium", "base-listing"),
    ("/actuator/env", "actuator-env-exposed", "critical", "env"),
    ("/actuator/heapdump", "actuator-heapdump", "critical", "binary"),
    ("/actuator/threaddump", "actuator-exposed", "medium", "json"),
    ("/actuator/httptrace", "actuator-exposed", "medium", "json"),
    ("/actuator/configprops", "actuator-env-exposed", "critical", "json"),
    ("/actuator/mappings", "actuator-exposed", "medium", "json"),
    ("/actuator/beans", "actuator-exposed", "medium", "json"),
    ("/env", "actuator-legacy-exposed", "medium", "json"),
    ("/heapdump", "actuator-legacy-exposed", "medium", "binary"),
    ("/trace", "actuator-legacy-exposed", "medium", "json"),
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


def _looks_json(body: str) -> bool:
    b = body.strip()[:1]
    return b in ("{", "[") and len(body.strip()) > 2


def _probe_positive(path: str, kind: str, resp: Optional[httpx.Response]
                    ) -> bool:
    """True when a probe reply indicates the endpoint is genuinely live and
    not an app-404 / soft page."""
    if resp is None:
        return False
    if resp.status_code not in (200, 206):
        return False
    body = resp.text or ""
    if kind == "binary":
        return len(body) > 1024
    return _looks_json(body)


@register
class SpringActuatorSkill(Skill):
    """Probe for exposed Spring Boot actuator endpoints."""

    name = "spring-actuator"
    display_name = "Spring Actuator"
    category = SkillCategory.WEB
    version = "1.0"

    requires_all: list[str] = ["tech_spring"]

    timeout_seconds = 60
    max_requests = 12

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"spring_scan": "no-target"}})

        root = base.rstrip("/")
        findings: list[RawFinding] = []
        exposed: list[str] = []

        with _client() as client:
            for path, template_id, severity, kind in _ACTUATOR_PROBES:
                url = root + path
                try:
                    resp = client.get(url, timeout=PROBE_TIMEOUT)
                except Exception:  # noqa: BLE001
                    continue
                if not _probe_positive(path, kind, resp):
                    continue
                exposed.append(path)
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id=template_id,
                    vulnerability_type="information_disclosure",
                    target=base, host=base,
                    severity=severity,
                    url=url,
                    description=(
                        f"Spring Boot actuator endpoint exposed: {path}"
                        + (" — environment/config may leak secrets"
                           if severity == "critical" else "")),
                    raw={
                        "endpoint": path,
                        "status": resp.status_code,
                        "kind": kind,
                    },
                ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"spring_actuator": "clear"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "spring_actuator": "exposed",
                "spring_exposed_endpoints": exposed}})