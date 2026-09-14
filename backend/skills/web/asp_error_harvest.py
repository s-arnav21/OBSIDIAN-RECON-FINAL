"""ASP / ASP.NET error-page harvest.

Classic ASP sites frequently ship with default error pages turned on, leaking
stack traces, connection strings and physical server file paths whenever a
script throws. Gated on ASP/IIS technology or the discovery of an .asp/.aspx
page.

What it does:
  - probes a small self-contained ASP wordlist (default.asp, login.asp,
    showforum.asp, ...) plus any .asp/.aspx pages already discovered
    (recon discovered_paths) and injection candidates (param_candidates),
  - scans each response body for three disclosure classes:
      * connection strings  -> ASP_CONNECTION_STRING (CRITICAL)
      * stack traces / error types -> ASP_STACK_TRACE (HIGH)
      * physical file paths -> ASP_FILE_PATH_DISCLOSURE (MEDIUM)

Bounded: concurrency-limited, capped total requests, capped findings.
Tools: nothing external (httpx).
"""
from __future__ import annotations

import re
import threading
from queue import Queue
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

_TIMEOUT = 12
_CONCURRENCY = 6
_MAX_REQUESTS = 48
_MAX_FINDINGS = 30
_BODY_CAP = 64 * 1024

_USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
               "educational security platform)")

# Self-contained probe set for classic ASP stacks. Pages famous for triggering
# rich error output (connection strings, tracebacks, physical paths).
_ASP_WORDLIST = [
    "default.asp", "index.asp", "login.asp", "admin.asp", "register.asp",
    "search.asp", "templatize.asp", "showforum.asp", "error.asp",
    "errorpage.asp", "global.asa", "trace.axd", "include/error.asp",
    "validate.asp", "process.asp", "database.asp",
]

_WEB_HINT_PORTS = (443, 8443, 80, 8080)

# Connection strings look like `Data Source=...;User Id=...;Password=...`
_CONNECTION_STRING_RE = re.compile(
    r"(?:data\s+source|server|provider|initial\s+catalog)[^<\"]{0,200}"
    r"(?:user\s+id|uid|pwd|password|pwd=)[^<\"]{0,80}",
    re.I,
)

_STACK_TRACE_MARKERS = (
    "error type:", "microsoft ole db", "microsoft vbscript runtime",
    "microsoft jscript runtime", "server error in '/' application",
    "server application unavailable", "stack trace", "exception details:",
    "an unhandled exception", "runtime error", "at system.",
    "at microsoft.", "vbscript", "description: the page",
)

_FILE_PATH_RE = re.compile(
    r"\b[a-zA-Z]:\\[\\\w ._/-]+|inetpub|wwwroot|"
    r"/home/[a-z0-9_.]+/public_html|/var/www|/srv/www",
    re.I,
)


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _base(ctx: SkillContext) -> Optional[str]:
    """Derive the probing origin from the context (host/scheme/open ports)."""
    host = _extract_host(ctx)
    if not host:
        return None
    scheme = (ctx.scheme or "https").lower()
    port = ctx.port or 0
    if port in (80, 8080):
        scheme = "http"
    elif port in (443, 8443):
        scheme = "https"
    for p in _WEB_HINT_PORTS:
        if p in ctx.open_ports:
            port = p
            scheme = "http" if p in (80, 8080) else "https"
            break
    netloc = host
    if port and not ((scheme == "http" and port == 80)
                     or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    return f"{scheme}://{netloc}"


def _candidate_urls(ctx: SkillContext, base: Optional[str]) -> list[str]:
    """Collect .asp/.aspx pages to probe from all context sources."""
    seen: set[str] = set()
    urls: list[str] = []

    def add(u: str) -> None:
        u = u.strip()
        if not u or u in seen:
            return
        seen.add(u)
        urls.append(u)

    for path in ctx.discovered_paths:
        low = str(path).lower()
        if ".asp" in low:
            if str(path).startswith(("http://", "https://")):
                add(str(path))
            elif base:
                add(f"{base}/{str(path).lstrip('/')}")

    for cand in ctx.param_candidates:
        url = (cand or {}).get("url") or ""
        if ".asp" in url.lower():
            add(url)

    if base:
        for p in _ASP_WORDLIST:
            add(f"{base}/{p}")
    return urls


def _findings_for_body(url: str, path: str, body: str,
                       status: Optional[int]) -> list[RawFinding]:
    """Classify one response body into ASP disclosure findings."""
    found: list[RawFinding] = []
    if not body:
        return found
    low = body.lower()

    conn_m = _CONNECTION_STRING_RE.search(body)
    if conn_m:
        found.append(RawFinding(
            scanner="skill:asp-error-harvest",
            scanner_template_id="asp-connection-string",
            vulnerability_type="information_disclosure",
            target=url, host=url,
            severity="critical",
            url=url, path=path,
            description=(
                f"connection string leaked in error output at {url}"
            ),
            raw={"url": url, "status": status,
                 "excerpt": re.sub(r"\s+", " ", conn_m.group(0)).strip()[:300]},
        ))

    trace_markers = sorted(
        {m for m in _STACK_TRACE_MARKERS if m in low})
    if trace_markers:
        idx = min((low.find(m) for m in trace_markers if low.find(m) >= 0),
                  default=0)
        found.append(RawFinding(
            scanner="skill:asp-error-harvest",
            scanner_template_id="asp-stack-trace",
            vulnerability_type="information_disclosure",
            target=url, host=url,
            severity="high",
            url=url, path=path,
            description=(
                f"server-side stack trace / error details leaked at {url} "
                f"({', '.join(trace_markers)})"
            ),
            raw={"url": url, "status": status,
                 "markers": trace_markers,
                 "excerpt": re.sub(r"\s+", " ", body[idx:idx + 300]).strip()},
        ))

    path_m = _FILE_PATH_RE.search(body)
    if path_m:
        found.append(RawFinding(
            scanner="skill:asp-error-harvest",
            scanner_template_id="asp-file-path-disclosure",
            vulnerability_type="information_disclosure",
            target=url, host=url,
            severity="medium",
            url=url, path=path,
            description=(
                f"physical server file path leaked in error output at {url}"
            ),
            raw={"url": url, "status": status,
                 "excerpt": re.sub(r"\s+", " ", path_m.group(0)).strip()[:300]},
        ))
    return found


def _probe_all(urls: list[str]) -> List[RawFinding]:
    """Concurrently GET each candidate URL and classify error output."""
    findings: List[RawFinding] = []
    lock = threading.Lock()

    def worker() -> None:
        client = httpx.Client(verify=False, timeout=_TIMEOUT,
                              follow_redirects=True,
                              headers={"User-Agent": _USER_AGENT})
        try:
            with client:
                # urls list is shared and shrunk; each worker pops from the end
                while True:
                    try:
                        url = urls.pop()
                    except IndexError:
                        return
                    try:
                        resp = client.get(url)
                        if resp.status_code not in (200, 500, 501, 502, 503):
                            continue
                        body = (resp.text or "")[:_BODY_CAP]
                    except Exception:  # noqa: BLE001 - timeout/refused
                        continue
                    for f in _findings_for_body(url, url, body, resp.status_code):
                        with lock:
                            findings.append(f)
                            if len(findings) >= _MAX_FINDINGS:
                                return
        finally:
            pass

    n = min(_CONCURRENCY, len(urls)) if urls else 0
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=_TIMEOUT + 10)

    return findings


@register
class AspErrorHarvestSkill(Skill):
    """Harvest ASP/ASP.NET error-page disclosures."""

    name = "asp-error-harvest"
    display_name = "ASP Error Page Harvest"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["tech_aspnet", "tech_iis", "asp_page_found"]

    timeout_seconds = 120
    max_requests = _MAX_REQUESTS

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(skill_name=self.name, success=True,
                               findings=[],
                               context_updates={"osint": {
                                   "asp_harvest": "no-target"}})

        base = _base(ctx)
        urls = _candidate_urls(ctx, base)
        if not urls:
            return SkillResult(skill_name=self.name, success=True,
                               findings=[],
                               context_updates={"osint": {
                                   "asp_harvest": "no-candidates"}})

        urls = urls[:_MAX_REQUESTS]
        findings = _probe_all(urls)

        osint = {"asp_harvest": {
            "base": base,
            "candidates": len(urls),
            "findings": len(findings),
        }}

        # Every probed ASP page is a candidate for downstream injection probes.
        param_candidates = [
            {"url": u, "param": None, "injectable": True,
             "trigger": "asp_error_harvest"}
            for u in urls
        ]

        if not findings:
            return SkillResult(skill_name=self.name, success=True,
                               findings=[],
                               context_updates={"osint": osint,
                                                "param_candidates": param_candidates})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint,
                             "param_candidates": param_candidates})