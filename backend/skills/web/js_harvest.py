"""JavaScript Harvest — fetch the target's homepage, discover script bundles,
and extract API endpoints + embedded secrets.

There was no legacy JS-harvest scanner; this skill implements the behaviour
natively on the Skill contract:

  1. Fetch {base}/ and collect same-origin <script src> URLs (plus any strings
     already discovered by content discovery that end in .js).
  2. Concurrently fetch each bundle (bounded).
  3. Endpoint harvest: pull route-looking string literals out of each bundle,
     normalize them to absolute URLs against the target origin, and surface
     them as INFO findings + `js_endpoints` context.
  4. Secret harvest: high-confidence pattern matches (AWS/Google/GitHub/Stripe/
     Slack/OpenAI/SendGrid/Twilio keys, PEM private keys) and sensitive-key
     assignments surface as HIGH findings (`js-secret-detected` template, which
     the selector maps to the `js_secret_found` condition).

Everything is bounded: max JS files, max endpoint/secret findings, per-request
timeouts. Tools: nothing external (httpx).
"""
from __future__ import annotations

import re
import threading
from queue import Queue
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

MAX_JS_FILES = 40
MAX_ENDPOINT_FINDINGS = 80
MAX_SECRET_FINDINGS = 20
PROBE_TIMEOUT = 10
PROBE_CONCURRENCY = 10

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

_SCRIPT_SRC_RE = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_PRELOAD_RE = re.compile(
    r"""<link\b[^>]*\brel\s*=\s*["'][^"']*preload[^"']*["'][^>]*\bhref\s*=\s*["']([^"']+)["']""",
    re.I)

# ---- high-confidence secret patterns ---------------------------------------
_AWS_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b")
_STRIPE_KEY = re.compile(r"\b(?:sk|pk)_(?:test|live)_[0-9A-Za-z]{16,}\b")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
_SENDGRID_KEY = re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b")
_TWILIO_KEY = re.compile(r"\bSK[0-9a-fA-F]{32}\b")
_SQUARE_KEY = re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")

_SENSITIVE_KEY_NAMES = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "api-key", "access_key", "access-key", "private_key", "private-key",
    "auth_token", "auth-token", "client_secret", "client-secret",
    "app_secret", "app-secret", "authsecret", "session_secret",
)
_GENERIC_ASSIGN_RE = re.compile(
    r"""\b(?P<key>[A-Za-z0-9_\-\.]{2,40})\s*[:=]\s*["'](?P<val>[^"']{6,200})["']""",
    re.I)

# Values that are obviously placeholders / urls / multi-item — never secrets.
_PLACEHOLDER_RE = re.compile(
    r"^(your-|your_|<|xxx|\.{3}|test|example|placeholder|changeme|process\.env"
    r"|getenv|new|null|undefined|https?://|//|javascript:|data:|\$|function)")

_SECRET_PATTERNS = [
    ("aws_access_key_id", _AWS_ACCESS_KEY),
    ("google_api_key", _GOOGLE_API_KEY),
    ("github_token", _GITHUB_TOKEN),
    ("stripe_api_key", _STRIPE_KEY),
    ("openai_api_key", _OPENAI_KEY),
    ("slack_token", _SLACK_TOKEN),
    ("sendgrid_api_key", _SENDGRID_KEY),
    ("twilio_api_key", _TWILIO_KEY),
    ("square_access_token", _SQUARE_KEY),
    ("private_key", _PRIVATE_KEY),
]

_SKIP_EXTS = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".map",
)
_SKIP_PREFIXES = ("#", "mailto:", "tel:", "data:", "javascript:", "ws://", "wss://")


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


def _same_origin(base: str, url: str) -> bool:
    bh = (urlparse(base).hostname or "").lower()
    uh = (urlparse(url).hostname or "").lower()
    return bh == uh or not uh


def _script_urls(html: str, base: str) -> list[str]:
    """Return absolute same-origin script srcs (deduped, input order)."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _SCRIPT_SRC_RE.finditer(html or ""):
        src = m.group(1).strip()
        if src.startswith(("#", "data:", "blob:")):
            continue
        url = urljoin(base, src)
        if _same_origin(base, url) and url not in seen:
            seen.add(url)
            out.append(url)
    for m in _PRELOAD_RE.finditer(html or ""):
        href = m.group(1).strip()
        url = urljoin(base, href)
        if _same_origin(base, url) and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _fetch_home(client: httpx.Client, base: str) -> str:
    try:
        resp = client.get(base + "/", timeout=PROBE_TIMEOUT)
        return resp.text or ""
    except Exception:  # noqa: BLE001
        return ""


def _fetch_js(client: httpx.Client, urls: list[str]) -> list[tuple[str, str]]:
    """Concurrently fetch the given JS URLs; returns (url, text) successes."""
    if not urls:
        return []
    results: list[tuple[str, str]] = []
    lock = threading.Lock()
    q: Queue = Queue()
    for u in urls:
        q.put(u)

    def worker() -> None:
        while True:
            try:
                url = q.get_nowait()
            except Exception:  # noqa: BLE001
                return
            try:
                resp = client.get(url, timeout=PROBE_TIMEOUT)
                text = resp.text or ""
                if text:
                    with lock:
                        results.append((url, text))
            except Exception:  # noqa: BLE001
                pass
            finally:
                q.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(PROBE_CONCURRENCY, len(urls)))]
    for t in threads:
        t.start()
    q.join()
    for t in threads:
        t.join()

    order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda item: order.get(item[0], len(urls)))
    return results


# route-looking string literal: "/something/deep/{param}" or full url
_STR_LITERAL_RE = re.compile(
    r"""["'`]([^"'`]{2,500})["'`]""")
_PATHISH_RE = re.compile(
    r"""^/(?!$)[A-Za-z0-9_\-./{}:\[\]]+$""")


def _extract_endpoints(js_text: str) -> list[str]:
    """Pull route-ish literals out of JS; return deduped, source-ordered."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _STR_LITERAL_RE.finditer(js_text or ""):
        lit = m.group(1)
        if "://" in lit:
            continue
        if not _PATHISH_RE.match(lit):
            continue
        low = lit.lower()
        if low.endswith(_SKIP_EXTS):
            continue
        if lit.startswith(_SKIP_PREFIXES):
            continue
        if lit.count("/") and len(lit) > 1 and lit not in seen:
            seen.add(lit)
            out.append(lit)
    return out


def _extract_secrets(js_text: str) -> list[dict]:
    """Return list of {type, value_preview, source_start} for detected secrets."""
    found: list[dict] = []
    for name, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(js_text or ""):
            preview = m.group(0)
            if len(preview) > 80:
                preview = preview[:80] + "..."
            found.append({"type": name, "value_preview": preview,
                          "source_start": m.start()})
    # sensitive-key assignments
    for m in _GENERIC_ASSIGN_RE.finditer(js_text or ""):
        key = (m.group("key") or "").replace(".", "_").replace("-", "_").lower()
        if key not in _SENSITIVE_KEY_NAMES:
            continue
        val = (m.group("val") or "").strip()
        if _PLACEHOLDER_RE.match(val):
            continue
        kind = "generic_secret_assignment"
        if key.startswith("password"):
            kind = "password_assignment"
        preview = val if len(val) <= 80 else val[:80] + "..."
        found.append({"type": kind, "value_preview": preview,
                      "source_start": m.start()})
    found.sort(key=lambda d: d["source_start"])
    return found


@register
class JsHarvestSkill(Skill):
    """Harvest JS bundles for API endpoints and embedded secrets."""

    name = "js-harvest"
    display_name = "JavaScript Harvest"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["port_80_open", "port_443_open"]

    timeout_seconds = 120
    max_requests = 120

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"js_harvest_skipped": True}})

        with _client() as client:
            html = _fetch_home(client, base)
            urls = _script_urls(html, base)
            for p in ctx.discovered_paths:
                p = (p or "").strip()
                if not p:
                    continue
                url = p if p.startswith(("http://", "https://")) else urljoin(base, p)
                if url.lower().endswith(".js") and _same_origin(base, url) \
                        and url not in urls:
                    urls.append(url)
            urls = urls[:MAX_JS_FILES]
            bundles = _fetch_js(client, urls)

        findings: list[RawFinding] = []
        js_endpoints: list[str] = []
        osint = {"js_base": base, "js_files": urls,
                 "js_secret_count": 0, "js_endpoint_count": 0}

        known_eps = set(ctx.js_endpoints)
        seen_eps: set[str] = set()

        def add_endpoints(url: str, text: str) -> None:
            for ep in _extract_endpoints(text):
                ep_abs = urljoin(base, ep)
                if ep_abs.startswith(_SKIP_PREFIXES) or ep_abs in seen_eps:
                    continue
                seen_eps.add(ep_abs)
                if ep_abs in known_eps:
                    continue
                osint["js_endpoint_count"] += 1
                js_endpoints.append(ep_abs)
                if len(seen_eps) <= MAX_ENDPOINT_FINDINGS:
                    findings.append(RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id="js-api-endpoint",
                        vulnerability_type="reconnaissance",
                        target=base, host=base,
                        severity="info",
                        url=ep_abs,
                        description=(f"API endpoint harvested from {url}: {ep_abs}"),
                        raw={"source": url, "endpoint": ep,
                             "endpoint_url": ep_abs},
                    ))

        def add_secrets(url: str, text: str) -> None:
            for s in _extract_secrets(text):
                osint["js_secret_count"] += 1
                if osint["js_secret_count"] > MAX_SECRET_FINDINGS:
                    continue
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="js-secret-detected",
                    vulnerability_type="information_disclosure",
                    target=base, host=base,
                    severity="high",
                    url=url,
                    description=(f"possible {s['type']} exposed in {url}: "
                                 f"'{s['value_preview']}'"),
                    raw={"secret_type": s["type"],
                         "value_preview": s["value_preview"],
                         "source": url},
                ))

        for url, text in bundles:
            add_endpoints(url, text)
            add_secrets(url, text)

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint, "js_endpoints": js_endpoints})