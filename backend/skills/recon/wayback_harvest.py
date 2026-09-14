"""Wayback Machine Harvest — historical URLs, paths, and subdomains.

The Internet Archive's Wayback CDX API returns every URL it has ever archived
for a domain. This is a passive treasure trove: it reveals historical paths
(including ones removed from the live site), query parameters, and subdomain
hostnames the target may have long forgotten.

From the CDX output this skill:
  * extracts distinct historical URLs (deduplicated),
  * derives discovery paths (host + path) for the content-discovery phase,
  * flags URLs whose path matches sensitive fingerprints (configs, backups,
    ".env", admin, debug, etc.),
  * merges co-archived subdomains back into the shared subdomain context.

Findings:
  - HISTORICAL_SENSITIVE_PATH (LOW) — archived URL exposed a sensitive path
Context:
  - discovered_paths (path+host, capped)
  - subdomains (hostnames from archived URLs)
Tools: nothing external (uses httpx against web.archive.org)
"""
from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TIMEOUT = 15
USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")
MAX_URLS = 500
MAX_PATHS = 300
MAX_SUBDOMAINS = 200

SENSITIVE_PATH = re.compile(
    r"(?i)(/\.env|/\.git|/config\.|/wp-config|/backup|/db\.sql|"
    r"/\.ssh|/id_rsa|/\.aws|\.bak$|~$|\.old$|\.log$|/admin|/debug|"
    r"/\.svn|\.phpunit|/_ignition|/dump\.sql|/\.htaccess|"
    r"/\.DS_Store|\.zip$|\.tar\.gz$|\.sql$)"
)


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _fetch_cdx(host: str) -> list[str]:
    """Fetch archived original URLs for a domain via the CDX API; [] on failure."""
    url = (
        "http://web.archive.org/cdx/search/cdx?url=*.{domain}&"
        "output=json&fl=original&collapse=urlkey&limit={limit}"
    ).format(domain=host, limit=MAX_URLS + 50)
    try:
        import json
        with _client() as c:
            r = c.get(url, timeout=TIMEOUT)
            rows = json.loads(r.text or "[]")
    except Exception:  # noqa: BLE001 - network / parse failure degrades quietly
        return []
    if not isinstance(rows, list):
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, list) or not row:
            continue
        u = row[0]
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
            if len(urls) >= MAX_URLS:
                break
    return urls


def _extract_params(url: str, max_params: int = 60) -> list[dict]:
    """Extract distinct query parameter names from one historical URL.

    Each entry is an injection candidate for the sqli-error / fuzz skills:
    {"url": full-archived-url, "param": name, "trigger": "wayback_param"}.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return []
    if not parsed.query:
        return []
    from urllib.parse import parse_qsl
    names: list[str] = []
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key and key not in names:
            names.append(key)
    return [
        {"url": url, "param": name, "injectable": False,
         "trigger": "wayback_param"}
        for name in names[:max_params]
    ]


def _parse_urls(urls: list[str], host: str) -> tuple[list[str], list[str], list[str], list[dict]]:
    """Return (subdomains, discovered_paths, sensitive_paths, param_candidates).

    param_candidates are {"url", "param", "injectable", "trigger"} dicts
    harvested from historical query strings (capped).
    """
    subdomains: set[str] = set()
    paths: set[str] = set()
    sensitive: list[str] = []
    param_candidates: list[dict] = []
    max_params_total = 60

    for raw in urls:
        try:
            parsed = urlparse(raw)
        except ValueError:
            continue
        if not parsed.hostname:
            continue
        h = parsed.hostname.lower().rstrip(".")
        # Only keep subdomains under the target domain.
        if h.endswith(f".{host}") and h != host:
            subdomains.add(h)

        # Build a discovery path entry: host + path (+ query, if tiny).
        path = parsed.path or "/"
        query = parsed.query
        entry = path
        if query and len(query) <= 80:
            entry = f"{path}?{query}"
        if entry not in paths:
            paths.add(entry)

        if parsed.query and len(param_candidates) < max_params_total:
            for cand in _extract_params(raw, max_params_total - len(param_candidates)):
                if not any(c["param"] == cand["param"]
                           for c in param_candidates):
                    param_candidates.append(cand)
                    if len(param_candidates) >= max_params_total:
                        break

        if SENSITIVE_PATH.search(parsed.path or ""):
            sensitive.append(raw)
            if len(sensitive) >= 5:
                break

    return (sorted(subdomains)[:MAX_SUBDOMAINS],
            sorted(paths)[:MAX_PATHS],
            sensitive,
            param_candidates[:max_params_total])


@register
class WaybackHarvestSkill(Skill):
    """Harvest historical URLs, paths, and subdomains from the Wayback Machine."""

    name = "wayback-harvest"
    display_name = "Wayback Machine Harvest"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 60
    max_requests = 1

    def should_run(self, ctx: SkillContext) -> bool:
        if not _extract_host(ctx):
            return False
        return not _is_ip(_extract_host(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        findings: list[RawFinding] = []
        osint_add = {}

        if not host or _is_ip(host):
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"wayback_skipped": True}})

        urls = _fetch_cdx(host)
        subdomains, paths, sensitive, param_candidates = _parse_urls(urls, host)

        osint_add["wayback_urls"] = urls[:100]
        osint_add["wayback_subdomains"] = subdomains

        new_paths = [p for p in paths if p not in set(ctx.discovered_paths)]
        known_subs = set(ctx.subdomains)
        new_subs = [s for s in subdomains if s not in known_subs]
        known_params = {(c.get("url"), c.get("param"))
                        for c in ctx.param_candidates}
        new_params = [c for c in param_candidates
                      if (c.get("url"), c.get("param")) not in known_params]

        if sensitive:
            found = sensitive[0]
            findings.append(self._sensitive_path(host, found))

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={
                "osint": osint_add,
                "discovered_paths": new_paths,
                "param_candidates": new_params,
                "subdomains": new_subs,
            })

    def _sensitive_path(self, host: str, url: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="historical-sensitive-path",
            vulnerability_type="information-disclosure",
            target=host, host=host,
            severity="low",
            description=(
                f"Sensitive path was publicly archived for {host}: {url[:140]} "
                f"— historical exposure of config/backup/admin content"
            ),
            raw={"host": host, "url": url[:500]},
        )
