"""WordPress-specific recon — targeted checks against a WordPress install.

Gated on `tech_wordpress` (the fingerprint skill must already have identified
WordPress). Runs four focused probes:

  1. wp-config.php exposure   — if a server hands back the raw PHP source
                                (DB_* constants / `<?php` / `define(`) the site
                                leaks its database credentials: CRITICAL.
  2. WP REST user enumeration — `/wp-json/wp/v2/users` returning author data
                                (id/slug/name) enables username harvesting.
  3. Plugin footprint         — a handful of very common plugin paths returning
                                a live plugin artifact => plugin list, useful
                                for known-exploit matching.
  4. xmlrpc.php               — system.listMethods reachable means brute-force
                                amplification and pingback SSRF vectors.

Probes stay quiet: 403/404 are treated as clean. Findings:
`wp-config-exposed` (CRITICAL), `wp-user-enum` (MEDIUM), `wp-plugin-found`
(INFO), `wp-xmlrpc-enabled` (MEDIUM). httpx only.
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

# A live artifact per plugin (relative to /wp-content/plugins/<slug>/).
_PLUGIN_PROBES = (
    "akismet/akismet.php",
    "contact-form-7/wp-contact-form-7.php",
    "elementor/elementor.php",
    "wordpress-seo/wp-seo.php",
    "jetpack/jetpack.php",
    "woocommerce/woocommerce.php",
    "wpforms-lite/wpforms.php",
    "classic-editor/classic-editor.php",
    "redirection/redirection.php",
    "all-in-one-seo-pack/all_in_one_seo_pack.php",
)

_XMLRPC_BODY = """<?xml version="1.0"?>
<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""

_WP_CONFIG_MARKERS = re.compile(
    r"(DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|"
    r"define\s*\(|<\?php)", re.I)
_USER_JSON_MARKER = re.compile(
    r'"id"\s*:\s*\d+\s*,\s*"name"', re.I)


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


# Path markers that pin down a WordPress application directory when it is not
# served from the document root (e.g. the app lives under /secret/). When a
# discovered path exposes one of these we probe under that directory instead
# of (or in addition to) the web root.
_WP_PATH_MARKERS = ("wp-admin", "wp-content", "wp-includes", "wp-login",
                    "xmlrpc.php", "wp-json", "wp-config")


def _discovered_wp_base(ctx: SkillContext) -> Optional[str]:
    """Return the deepest WordPress app directory seen in discovered paths.

    Probes like `/secret/wp-login.php` or `/secret/xmlrpc.php` reveal that the
    WordPress install sits under `/secret/`. Scanning only the root would miss
    it, so derive the app base from the URL prefix up to (not including) the
    wp-* marker and probe there.
    """
    host = _extract_host(ctx)
    if not host:
        return None
    best: Optional[str] = None
    for p in ctx.discovered_paths:
        low = (p or "").lower()
        marker_pos = None
        for marker in _WP_PATH_MARKERS:
            idx = low.find(marker)
            if idx == -1:
                continue
            marker_pos = idx if marker_pos is None else min(marker_pos, idx)
        if marker_pos is None:
            continue
        app_dir = p[:marker_pos].rstrip("/")
        if app_dir and (
                best is None
                or app_dir.count("/") > best.count("/")):
            best = app_dir
    if not best:
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
    return f"{scheme}://{netloc}{best if best.startswith('/') else '/' + best}"


def _client() -> httpx.Client:
    return httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _get(client: httpx.Client, url: str) -> Optional[httpx.Response]:
    try:
        return client.get(url, timeout=PROBE_TIMEOUT)
    except Exception:  # noqa: BLE001
        return None


def _config_exposed(resp: Optional[httpx.Response]) -> bool:
    """True when wp-config.php answers with raw PHP source."""
    if resp is None:
        return False
    if resp.status_code not in (200, 206):
        return False
    body = resp.text or ""
    if len(body) < 5:
        return False
    return bool(_WP_CONFIG_MARKERS.search(body))


def _users_enum(resp: Optional[httpx.Response]) -> bool:
    if resp is None or resp.status_code != 200:
        return False
    body = resp.text or ""
    return bool(body) and bool(_USER_JSON_MARKER.search(body))


def _xmlrpc_enabled(resp: Optional[httpx.Response]) -> bool:
    if resp is None:
        return False
    if resp.status_code != 200:
        return False
    body = resp.text or ""
    # A well-formed XML-RPC exchange answers with a <methodResponse> — either
    # params or a fault. A fault (e.g. "parse error") still proves the server
    # executed the handler and echoes the request, i.e. xmlrpc.php is live.
    return bool(re.search(
        r"<methodResponse|methodCall|listMethods|<params>|<fault", body))


def _plugin_found(resp: Optional[httpx.Response]) -> bool:
    if resp is None:
        return False
    ok_status = 200 <= resp.status_code < 400
    if not ok_status:
        return False
    body = (resp.text or "").lower()
    return bool(body) and ("plugin" in body or "wordpress" in body.lower()
                           or ".php" in body or len(body) > 50)


@register
class WordpressScanSkill(Skill):
    """WordPress-specific exposure checks (wp-config, REST users, plugins,
    xmlrpc)."""

    name = "wordpress-scan"
    display_name = "WordPress Scan"
    category = SkillCategory.WEB
    version = "1.0"

    requires_all: list[str] = ["tech_wordpress"]

    timeout_seconds = 60
    max_requests = 15

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"wordpress_scan": "no-target"}})

        # WordPress may live under a subdirectory (e.g. /secret/) rather than
        # the document root. Prefer the deepest app directory seen during
        # content discovery so the four probes hit the real install.
        root = (_discovered_wp_base(ctx) or base).rstrip("/")
        findings: list[RawFinding] = []
        notes: dict = {"app_dir": root}

        with _client() as client:
            config_resp = _get(client, root + "/wp-config.php")
            if _config_exposed(config_resp):
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="wp-config-exposed",
                    vulnerability_type="information_disclosure",
                    target=base, host=base,
                    severity="critical",
                    url=root + "/wp-config.php",
                    description=(
                        "wp-config.php served as raw PHP source — database "
                        "credentials exposed"),
                    raw={"status": config_resp.status_code,
                         "logger": "raw-php-source"},
                ))
                notes["config_exposed"] = True

            users_resp = _get(client, root + "/wp-json/wp/v2/users")
            if _users_enum(users_resp):
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="wp-user-enum",
                    vulnerability_type="information_disclosure",
                    target=base, host=base,
                    severity="medium",
                    url=root + "/wp-json/wp/v2/users",
                    description=(
                        "WordPress REST API exposes user metadata "
                        "(id/name/slug) via /wp-json/wp/v2/users"),
                    raw={"status": users_resp.status_code},
                ))
                notes["users_enum"] = True

            plugins: list[str] = []
            for plugin in _PLUGIN_PROBES:
                resp = _get(client, root + "/wp-content/plugins/" + plugin)
                if _plugin_found(resp):
                    plugins.append(plugin)
            if plugins:
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="wp-plugin-found",
                    vulnerability_type="wordpress",
                    target=base, host=base,
                    severity="info",
                    url=root + "/wp-content/plugins/",
                    description=(
                        "installed WordPress plugins detectable "
                        f"({', '.join(sorted(p.split('/')[0] for p in plugins))})"),
                    raw={"plugins": sorted(plugins)},
                ))
                notes["plugins"] = plugins

            xmlrpc_resp = client.post(root + "/xmlrpc.php",
                                      content=_XMLRPC_BODY,
                                      headers={"Content-Type": "text/xml"},
                                      timeout=PROBE_TIMEOUT)
            if _xmlrpc_enabled(xmlrpc_resp):
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="wp-xmlrpc-enabled",
                    vulnerability_type="wordpress",
                    target=base, host=base,
                    severity="medium",
                    url=root + "/xmlrpc.php",
                    description=(
                        "xmlrpc.php responds to system.listMethods — "
                        "brute-force amplification / pingback SSRF vector"),
                    raw={"status": xmlrpc_resp.status_code},
                ))
                notes["xmlrpc"] = True

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"wordpress_scan": "clear"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {"wordpress_scan": notes}})