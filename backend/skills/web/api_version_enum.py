"""API Version Enumeration — probe common versioned/unversioned API mount
points once any `/api` surface has been discovered.

Runs when recon/content discovery hinted at an API (`api_found`). It locates
the API base path(s) from `discovered_paths` / `js_endpoints` (plus the common
`/api` root) and probes each known version segment (v0–v6, latest, beta,
alpha, internal, admin, staging, dev, …) with a JSON-request GET. A response
that is anything other than `404/410` is treated as a live version.

Findings:
  - API_VERSION_FOUND (MEDIUM by default; HIGH for internal/admin/beta-style
    segments and for unversioned-oldest versions that should not be public)
Context:
  - osint.api_bases, osint.api_versions
Tools: nothing external (httpx).
"""
from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

MAX_CANDIDATE_BASES = 20
PROBE_TIMEOUT = 10

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

_VERSION_NAMES = (
    "v0", "v1", "v2", "v3", "v4", "v5", "v6",
    "latest", "beta", "alpha", "internal", "admin", "staging",
    "dev", "test", "preprod", "pre-production", "edge",
)

# segments that are sensitive / should never be publicly reachable
_HIGH_VERSION_NAMES = {
    "internal", "admin", "debug", "alpha", "beta", "latest",
    "dev", "test", "preprod", "pre-production", "edge", "v0",
}

# status codes that prove a version is live; everything else (404/410/429/5xx
# infra errors) means the segment is absent.
_FOUND_STATUS = {200, 201, 202, 203, 204, 301, 302, 307, 308,
                 401, 403, 405, 406, 409, 500}

_API_SEGMENT_RE = re.compile(r"/api(?:/|$)", re.I)


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


def _origin(base: str) -> str:
    p = urlparse(base)
    return f"{p.scheme}://{p.netloc}"


def _client() -> httpx.Client:
    return httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _api_bases(ctx: SkillContext, base: str) -> list[str]:
    """Locate API base path(s) from discovered paths / js endpoints."""
    origin = _origin(base)
    bases: list[str] = []
    seen: set[str] = set()

    def add(b: str) -> None:
        if b and b not in seen:
            seen.add(b)
            bases.append(b)

    add(origin + "/api")
    for p in list(ctx.discovered_paths) + list(ctx.js_endpoints):
        p = (p or "").strip()
        if not p:
            continue
        url = p if p.startswith(("http://", "https://")) else urljoin(base, p)
        if "graphql" in url.lower():
            continue
        path = urlparse(url).path or "/"
        m = _API_SEGMENT_RE.search(path)
        if not m:
            continue
        add(origin + path[:m.start() + 4])
    return bases[:MAX_CANDIDATE_BASES]


def _version_probe(client: httpx.Client, url: str) -> Optional[int]:
    """GET a versioned URL expecting JSON; returns status or None on error."""
    try:
        resp = client.get(url, headers={"Accept": "application/json"},
                          timeout=PROBE_TIMEOUT)
        return resp.status_code
    except Exception:  # noqa: BLE001 - timeout / conn error
        return None


def _severity(version: str, status: int) -> str:
    v = version.lower()
    if v in _HIGH_VERSION_NAMES:
        return "high"
    if 200 <= status < 300:
        return "medium"
    return "medium"


@register
class ApiVersionEnumSkill(Skill):
    """Enumerate versioned API mount points on discovered API bases."""

    name = "api-version-enum"
    display_name = "API Version Enumeration"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["api_found"]

    timeout_seconds = 90
    max_requests = 120

    def should_run(self, ctx: SkillContext) -> bool:
        base = _base(ctx)
        return bool(base) and bool(_api_bases(ctx, base))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"api_enum_skipped": True}})

        api_bases = _api_bases(ctx, base)
        findings: list[RawFinding] = []
        found_versions: list[dict] = []

        with _client() as client:
            for api_base in api_bases:
                for ver in _VERSION_NAMES:
                    url = f"{api_base}/{ver}"
                    status = _version_probe(client, url)
                    if status is None or status not in _FOUND_STATUS:
                        continue
                    found_versions.append({
                        "api_base": api_base, "version": ver, "status": status,
                    })
                    findings.append(RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id="api-version-found",
                        vulnerability_type="reconnaissance",
                        target=base, host=base,
                        severity=_severity(ver, status),
                        url=url,
                        description=(
                            f"API version endpoint reachable: {url} "
                            f"(status {status})"),
                        raw={"api_base": api_base, "version": ver,
                             "status": status},
                    ))

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "api_bases": api_bases,
                "api_versions": found_versions,
            }})