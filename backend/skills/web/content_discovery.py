"""Content Discovery — embedded wordlist + concurrent probing with soft-404
filtering.

The old content-discovery logic lived in the `content` + `content_httpx`
scanners; this skill replaces it while speaking the Skill contract. It
brute-forces the shared embedded high-value path wordlist against the target
origin, filters responses through the same soft-404 fingerprint machinery
(building a "guaranteed 404" profile per target, then suppressing anything
that matches it — important for SPAs that 200 everything), validates bodies
against path-expected keywords, and optionally downgrades/suppresses
findings that fail validation.

What it produces:
  - DISCOVERED_PATH finding per real hit (severity from the path type +
    status, e.g. CRITICAL for exposed .env / git, HIGH for admin panels)
  - discovered_paths context (new paths only) so downstream skills can react
    (selector derives admin_path_found / api_found / graphql_found tokens)

Bounded: concurrency, wordlist size, and a hard cap on emitted findings.
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
from pipeline.scanner.content import severity_for_path
from pipeline.scanner.content_httpx import (
    COMMON_PATHS,
    MAX_CONTENT_FINDINGS,
    PROBE_TIMEOUT,
    Soft404Profile,
    _SENSITIVE_PATHS,
    _body_validation,
    _build_soft_404_profile,
    _downgrade,
    _has_password_form,
    _is_dynamic_path,
    _is_frontpage_path,
    is_soft_404,
    should_emit_finding,
)
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_CONCURRENCY = 20
_BODY_SAMPLE = 16 * 1024

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

_WEB_HINT_PORTS = (443, 8443, 80, 8080)


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


def _client() -> httpx.Client:
    return httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _parse_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def _query_params(path: str) -> list[str]:
    """Extract distinct query parameter names from a path (may include '?')."""
    from urllib.parse import parse_qsl
    if "?" not in path:
        return []
    query = path.split("?", 1)[1].split("#", 1)[0]
    names = []
    for key, _ in parse_qsl(query, keep_blank_values=True):
        if key and key not in names:
            names.append(key)
    return names


def _probe(client: httpx.Client, base: str, paths: list[str],
           profile: Soft404Profile) -> list[tuple[str, dict]]:
    """Concurrently GET each path; return (url, info) for non-soft-404 hits.

    `info` keys: path, status, content_length, content_type, title, body.
    """
    q: Queue = Queue()
    for p in paths:
        q.put(p)
    lock = threading.Lock()
    results: list[tuple[str, dict]] = []

    def worker() -> None:
        while True:
            try:
                path = q.get_nowait()
            except Exception:  # noqa: BLE001 - empty queue
                return
            url = f"{base}/{path}"
            try:
                resp = client.get(url, timeout=PROBE_TIMEOUT)
                status = resp.status_code
                if not should_emit_finding(path, status):
                    continue
                if status not in (200, 201, 202, 204, 206, 301, 302, 403):
                    # A 500 on a dynamic page is an injection-relevant finding.
                    if not (status == 500 and _is_dynamic_path(path)):
                        continue
                body = (resp.text or "")[:_BODY_SAMPLE]
                body_len = len(resp.content) if resp.content else 0
                title = _parse_title(body)
                if is_soft_404(resp.status_code, body, body_len, title, profile):
                    continue
                with lock:
                    results.append((
                        url,
                        {
                            "path": path,
                            "status": resp.status_code,
                            "content_length": body_len,
                            "content_type": resp.headers.get("content-type"),
                            "title": title,
                            "body": body,
                        },
                    ))
            except Exception:  # noqa: BLE001 - timeout/refused/conn error
                pass
            finally:
                q.task_done()

    n = min(PROBE_CONCURRENCY, len(paths)) if paths else 0
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(n)]
    for t in threads:
        t.start()
    q.join()
    for t in threads:
        t.join()

    order = {p: i for i, p in enumerate(paths)}
    results.sort(key=lambda item: order.get(item[1]["path"], len(paths)))
    return results


@register
class ContentDiscoverySkill(Skill):
    """Brute-force high-value web paths against the target origin."""

    name = "content-discovery"
    display_name = "Content Discovery"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = [
        "port_80_open", "port_443_open", "port_8080_open", "port_8443_open",
    ]

    timeout_seconds = 180
    max_requests = 700

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"content_discovery_skipped": True}})

        with _client() as client:
            profile = _build_soft_404_profile(client, base)
            probes = _probe(client, base, COMMON_PATHS, profile)

        findings: list[RawFinding] = []
        discovered: list[str] = []
        param_candidates: list[dict] = []
        known = set(ctx.discovered_paths)
        stats = {"suspect": 0, "downgraded": 0, "suppressed": 0}

        for url, info in probes:
            path = info.get("path") or ""
            body = info.get("body") or ""

            # Body content validation: path responded but body lacks expected
            # content -> suspicious (downgrade, or suppress when INFO).
            note = _body_validation(path, body)
            if note:
                stats["suspect"] += 1

            sev = severity_for_path(
                path, info.get("status"),
                {"body_length": info.get("content_length"),
                 "title": info.get("title")},
            )

            if note:
                new_sev = _downgrade(sev)
                if new_sev is None:
                    stats["suppressed"] += 1
                    continue
                stats["downgraded"] += 1
                sev = new_sev

            raw = {
                "url": url,
                "status": info.get("status"),
                "content_length": info.get("content_length"),
                "content_type": info.get("content_type"),
                "title": info.get("title"),
                "sensitive": path in _SENSITIVE_PATHS,
            }
            description = (
                f"discovered path: {url} "
                f"({info.get('status')}, {info.get('content_length') or '?'} bytes"
                + (f", '{info.get('title')}'" if info.get("title") else "")
                + ")"
            )

            is_server_error = (info.get("status") == 500 and _is_dynamic_path(path))
            if is_server_error:
                # A 500 on a dynamic page is an injection-relevant finding.
                sev = "medium"
                raw["injectable"] = True
                raw["trigger"] = "500_on_dynamic"
                raw["body_excerpt"] = re.sub(r"\s+", " ", body).strip()[:300]
                description += (" — server error on dynamic page, "
                                "possible injection point")
                param_candidates.append({"url": url, "param": None,
                                         "injectable": True,
                                         "trigger": "500_on_dynamic"})
            elif "?" in path:
                for name in _query_params(path):
                    param_candidates.append({"url": url, "param": name,
                                             "injectable": False,
                                             "trigger": "discovered_query"})

            if note:
                raw["body_validation"] = note
                description += f" — {note}"

            findings.append(
                RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="discovered-path",
                    vulnerability_type="reconnaissance",
                    target=base,
                    host=base,
                    severity=sev,
                    url=url,
                    path=path,
                    description=description,
                    raw=raw,
                )
            )

            if _is_frontpage_path(path) and not is_server_error:
                findings.append(
                    RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id="frontpage-extensions",
                        vulnerability_type="frontpage-extensions",
                        target=base,
                        host=base,
                        severity="medium",
                        url=url,
                        path=path,
                        description=(
                            f"FrontPage Server Extensions directory exposed at "
                            f"{url} — legacy FPSE is a known attack surface "
                            f"(CVE-2000-0386 class)"
                        ),
                        raw={"url": url, "path": path,
                             "status": info.get("status")},
                    )
                )

            if _has_password_form(body):
                findings.append(
                    RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id="login-form-found",
                        vulnerability_type="login-form-found",
                        target=base,
                        host=base,
                        severity="info",
                        url=url,
                        path=path,
                        description=f"login form with password field at {url}",
                        raw={"url": url, "path": path},
                    )
                )

            if path not in known:
                discovered.append(path)
            if len(findings) >= MAX_CONTENT_FINDINGS:
                break

        osint = {
            "content_base": base,
            "paths_probed": len(COMMON_PATHS),
            "content_stats": stats,
        }
        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={
                "osint": osint,
                "discovered_paths": discovered,
                "param_candidates": param_candidates,
            })