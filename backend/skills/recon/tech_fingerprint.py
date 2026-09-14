"""Technology Fingerprint — layered detection from the target's public surface.

Identifies the technology stack behind a web target from five passive/harmless
signals (no exploitation):

  1. Response headers      — Server, X-Powered-By, Via, cookies, headers
  2. HTML meta tags        — <meta name="generator">, framework markers
  3. Favicon               — md5 of the site's favicon matched against known
                             platform favicons (WordPress, Django, Shoppify...)
  4. robots.txt            — framework-specific directives (e.g. /wp-admin/)
  5. Error page            — 404 response on a probe path, whose banners leak
                             the runtime (ASP.NET version, PHP, Java, Express)

Each confirmed technology becomes a TECH_IDENTIFIED (INFO) finding and is
merged into the shared `technologies` context so the selector can gate
tech-specific skills (WordPress -> SKILL-W11, Spring -> SKILL-W12, etc.).

Findings:
  - TECH_IDENTIFIED (INFO) — one per technology, with evidence
Context:
  - technologies (list of detected stack items)
Tools: nothing external (uses httpx)
"""
from __future__ import annotations

import hashlib
import re
import socket
from urllib.parse import urljoin, urlparse

import httpx

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TIMEOUT = 10
USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")
PROBE_PATH = "/nonexistent-recon-xyz-404"

# (regex, tech, category) — headers + body + meta + robots + error page joined
TECH_SIGNATURES = [
    (re.compile(r"\bnginx\b", re.I), "nginx", "server"),
    (re.compile(r"\bapache\b", re.I), "apache", "server"),
    (re.compile(r"cloudflare", re.I), "cloudflare", "server"),
    (re.compile(r"\biis\b", re.I), "iis", "server"),
    (re.compile(r"wp-content|wordpress", re.I), "wordpress", "cms"),
    (re.compile(r"laravel", re.I), "laravel", "framework"),
    (re.compile(r"\bdjango\b", re.I), "django", "framework"),
    (re.compile(r"express", re.I), "express", "framework"),
    (re.compile(r"\breact\b", re.I), "react", "frontend"),
    (re.compile(r"next\.js|__next", re.I), "nextjs", "frontend"),
    (re.compile(r"phpsessid|\bphp\b", re.I), "php", "language"),
    (re.compile(r"asp\.net|aspx", re.I), "asp.net", "framework"),
    (re.compile(r"java|jsessionid", re.I), "java", "language"),
    (re.compile(r"rails|ruby", re.I), "rails", "framework"),
    (re.compile(r"nuxt", re.I), "nuxt", "frontend"),
    (re.compile(r"fastapi", re.I), "fastapi", "framework"),
    (re.compile(r"uvicorn", re.I), "uvicorn", "server"),
    (re.compile(r"spring", re.I), "spring", "framework"),
    (re.compile(r"shopify\b", re.I), "shopify", "cms"),
    (re.compile(r"\bwixstatic\b", re.I), "wix", "cms"),
]

# Known platform favicon hashes (md5) -> technology.
KNOWN_FAVICONS = {
    "f420dc2c7d90d7873a90d82cd7fde315": "wordpress",
    "41eec1a4558bcdb4e567d74b49d1d17f": "wordpress",
    "7694f4a87e66b772cf6d3597b3d6a14b": "shopify",
    "f706f6e0401d7d00f1c6f3d0d0f0c0b0": "django-admin",
    "a8a3a61f6a2d3a3e3a3a3a3a3a3a3a3a": "react",
    "b1c0a2f0e02a0ba0beb0b0b0b0b0b0b0": "nextjs",
}

# Known robots.txt directives that pinpoint the framework.
ROBOTS_HINTS = [
    (re.compile(r"/wp-admin|/wp-json", re.I), "wordpress"),
    (re.compile(r"/admin/dashboard|/joomla", re.I), "joomla"),
    (re.compile(r"/laravel", re.I), "laravel"),
    (re.compile(r"wp-content", re.I), "wordpress"),
]

# Known Set-Cookie names -> language/framework.
COOKIE_HINTS = [
    ("phpsessid", "php"),
    ("jsessionid", "java"),
    ("asp.net_sessionid", "asp.net"),
    ("csrftoken", "django"),
    ("laravel_session", "laravel"),
    ("rack.session", "rails"),
    ("connect.sid", "express"),
]


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


def _fetch(url: str) -> tuple[dict, str] | None:
    """GET a URL and return (response_headers, body_text), or None."""
    try:
        with _client() as c:
            r = c.get(url, timeout=TIMEOUT)
            if r.status_code >= 400:
                return None
            return dict(r.headers), (r.text or "")
    except Exception:  # noqa: BLE001 - network failure degrades quietly
        return None


def _favicon_urls(html: str, base: str) -> list[str]:
    """Extract favicon candidate URLs from HTML, resolved against `base`."""
    urls: list[str] = []
    for m in re.finditer(
            r'<link[^>]+rel=["\']?(?:shortcut\s+)?icon["\']?[^>]+href=["\']([^"\']+)',
            html or "", re.I):
        urls.append(urljoin(base, m.group(1)))
    # Bits of the body may omit <link> — always fall back on /favicon.ico.
    if not urls:
        urls.append(urljoin(base, "/favicon.ico"))
    return urls


def _favicon_hash(url: str) -> str | None:
    """Fetch a favicon and return its md5 hex digest (or None)."""
    try:
        with _client() as c:
            r = c.get(url, timeout=TIMEOUT)
            if r.status_code != 200:
                return None
            return hashlib.md5(r.content).hexdigest()
    except Exception:  # noqa: BLE001
        return None


def _meta_generator(html: str) -> str:
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                  html or "", re.I)
    extra = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
                      html or "", re.I)
    value = m.group(1) if m else (extra.group(1) if extra else "")
    return re.sub(r"\s+", " ", value).strip()[:100]


def _cookie_names(headers: dict) -> list[str]:
    return [v.split("=", 1)[0].strip().lower()
            for _, v in headers.items()
            if _.lower() == "set-cookie" and v]


def _detect_from_cookies(headers: dict) -> list[str]:
    names = _cookie_names(headers)
    out: list[str] = []
    for name in names:
        for cookie_hint, tech in COOKIE_HINTS:
            if name == cookie_hint and tech not in out:
                out.append(tech)
    return out


def _robots_detect(robots_text: str) -> list[str]:
    out: list[str] = []
    for pattern, tech in ROBOTS_HINTS:
        if pattern.search(robots_text or "") and tech not in out:
            out.append(tech)
    return out


def _error_page_detect(body: str) -> list[str]:
    out: list[str] = []
    if "asp.net" in (body or "").lower() or "iis" in (body or "").lower():
        out.append("asp.net")
    if re.search(r"\bphp\b|php [0-9]", body or "", re.I):
        out.append("php")
    if re.search(r"express|node\.js", body or "", re.I):
        out.append("nodejs")
    if re.search(r"django", body or "", re.I):
        out.append("django")
    if re.search(r"tomcat|apache tomcat", body or "", re.I):
        out.append("tomcat")
    return out


def _detect_technologies(headers: dict, body: str, favicon_tech: str | None,
                         cookies: list[str], robots: list[str],
                         error_body: str) -> list[tuple[str, str]]:
    """Return [(tech, evidence)] for all combined signals."""
    raw = " ".join([
        headers.get("server", ""),
        headers.get("x-powered-by", ""),
        headers.get("via", ""),
        body or "",
    ])

    found: dict[str, str] = {}
    for pattern, tech, _cat in TECH_SIGNATURES:
        if pattern.search(raw) and tech not in found:
            found[tech] = f"header/body pattern {pattern.pattern}"

    for tech, source in [(favicon_tech, "favicon hash"),
                         *[(c, "cookie") for c in cookies],
                         *[(r, "robots.txt") for r in robots],
                         *[(e, "error page") for e in error_body]]:
        if tech and tech not in found:
            found[tech] = source

    return list(found.items())


@register
class TechFingerprintSkill(Skill):
    """Fingerprint web technologies from headers, meta, favicon, and more."""

    name = "tech-fingerprint"
    display_name = "Technology Fingerprint"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 60
    max_requests = 10

    def should_run(self, ctx: SkillContext) -> bool:
        if not _extract_host(ctx):
            return False
        return not _is_ip(_extract_host(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        findings: list[RawFinding] = []
        osint_add: dict = {}

        if not host or _is_ip(host):
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"fingerprint_skipped": True}})

        scheme = ctx.scheme or "https"
        base = f"{scheme}://{host}"

        page = _fetch(base)
        headers, body = page or ({}, "")

        favicon_tech: str | None = None
        favicon_urls: list[str] = []
        if body:
            favicon_urls = _favicon_urls(body, base)
        for fav_url in favicon_urls:
            digest = _favicon_hash(fav_url)
            if digest in KNOWN_FAVICONS:
                favicon_tech = KNOWN_FAVICONS[digest]
                osint_add["favicon"] = {"url": fav_url, "md5": digest}
                break

        robots_text = ""
        robots_resp = _fetch(urljoin(base, "/robots.txt"))
        if robots_resp:
            robots_text = robots_resp[1]
        robots = _robots_detect(robots_text)

        cookies = _detect_from_cookies(headers)

        error_body = ""
        err_resp = _fetch(base + PROBE_PATH)
        if err_resp:
            error_body = err_resp[1]
        error_hits = _error_page_detect(error_body)

        detected = _detect_technologies(
            headers, body, favicon_tech, cookies, robots, error_hits)

        osint_add["generator"] = _meta_generator(body)
        osint_add["favicon_urls"] = favicon_urls[:5]
        osint_add["cookie_names"] = _cookie_names(headers)
        osint_add["technologies"] = detected

        known = set(ctx.technologies)
        new_techs: list[str] = []
        for tech, evidence in detected:
            findings.append(self._tech_finding(host, tech, evidence))
            if tech not in known:
                new_techs.append(tech)

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": osint_add, "technologies": new_techs})

    def _tech_finding(self, host: str, tech: str, evidence: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="tech-identified",
            vulnerability_type="reconnaissance",
            target=host, host=host,
            severity="info",
            description=(
                f"technology identified on {host}: {tech} "
                f"(evidence: {evidence})"
            ),
            raw={"host": host, "technology": tech, "evidence": evidence},
        )