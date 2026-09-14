"""httpx-based path/content prober (no feroxbuster / external wordlist required).

Brute-forces a set of high-value paths against a single base URL using the
Python `httpx` library as a concurrent prober (replacing the missing Go
`httpx` CLI and `feroxbuster`). The wordlist is EMBEDDED in this module so no
external dictionary file is required.

Probing behaviour matches feroxbuster's bounded style:
  - GET on {base}/{path} for each candidate
  - Status codes of interest: 200/301/302/403 (configurable)
  - Emits an `info` RawFinding per hit with URL, status, content-length, title

Everything is bounded: concurrency, candidate count, and a hard cap on the
number of emitted findings.
"""
from __future__ import annotations

import hashlib
import re
import threading
import uuid
from dataclasses import dataclass, field
from queue import Queue
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from pipeline.scanner import base

MAX_CONTENT_FINDINGS = 200
PROBE_CONCURRENCY = 20
PROBE_TIMEOUT = 10
INTERESTING_STATUS = {200, 201, 202, 204, 206, 302, 301, 403}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Applications are often installed below the document root (e.g. a WordPress
# site at /secret/). After the one-level probe pass, each discovered directory
# is expanded with these sub-paths so nested apps are surfaced. Bounded: at
# most MAX_SUBDIR_PROBES directories are expanded.
_WP_SUBPROBES = (
    "wp-config.php",
    "wp-admin",
    "wp-admin/",
    "wp-login.php",
    "xmlrpc.php",
    "wp-json/wp/v2/users",
    "wp-includes/",
    "wp-content/",
    "index.php",
)
MAX_SUBDIR_PROBES = 10

# Bare status pages that respond 200 but are never an app directory to expand.
_NON_DIR_PATHS = {
    "status", "server-status", "server-info", "info", "healthz", "readyz",
    "alive", "whoami", "index",
}

# Static asset extensions that are pure noise as findings (an image/css/js file
# answering is not a vulnerability). Suppressed unconditionally.
STATIC_EXTENSIONS = {
    ".gif", ".jpg", ".jpeg", ".png", ".svg", ".webp",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
    ".ico", ".map",
}

# Dynamic script extensions — an HTTP 500 on one of these is a meaningful
# finding: the page executes server-side code and error behavior may be an
# injection point.
DYNAMIC_EXTENSIONS = (
    ".asp", ".aspx", ".php", ".jsp", ".jspx", ".cfm",
    ".do", ".action", ".aspx", ".asmx", ".axd",
)

# FrontPage Server Extensions artifacts (CWE-16 / A05 security misconfiguration).
_FRONTPAGE_PATHS = {
    "_vti_cnf", "_vti_bin", "_vti_pvt", "_vti_log", "_vti_txt",
    "_vti_script", "_vti_inf.html",
    "_vti_bin/_vti_aut/author.dll",
    "_vti_bin/_vti_adm/admin.dll",
}

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")


def _is_static_asset(path: str) -> bool:
    """True when the path is a static asset whose discovery is pure noise."""
    low = (path or "").lower()
    return any(low.endswith(ext) for ext in STATIC_EXTENSIONS)


def should_emit_finding(path: str, status: int) -> bool:
    """Shared gate: static assets are never emitted, everything else is."""
    return not _is_static_asset(path)


def _is_dynamic_path(path: str) -> bool:
    """True when the path targets a server-side script that can 500."""
    low = (path or "").lower().split("?", 1)[0].split("#", 1)[0]
    return any(low.endswith(ext) for ext in DYNAMIC_EXTENSIONS)


def _is_frontpage_path(path: str) -> bool:
    """True when the path is a FrontPage Server Extensions artifact."""
    low = (path or "").lower()
    return any(seg in low for seg in _FRONTPAGE_PATHS)


_PASSWORD_INPUT_RE = re.compile(
    r"""<input\b[^>]*?type\s*=\s*["']?password["']?[^>]*>""", re.I)


def _has_password_form(body: str) -> bool:
    """True when the body contains an HTML form with a password field."""
    return bool(_PASSWORD_INPUT_RE.search(body or ""))

# High-value paths embedded so no external wordlist is needed (~500+ paths).
# Grouped by the BUG 2 severity categories so a path's intended sensitivity is
# self-documenting.
_COMMON_PATHS_SETS = [
    # ---- config / secrets ----
    ".env", ".env.local", ".env.production", ".env.backup", ".env.old",
    ".env.example", ".env.sample", "config.php", "config.ini", "config.yaml",
    "config.yml", "config.json", "config.xml", "wp-config.php", "wconfig.php",
    "settings.py", "settings.php", "settings.json", "settings.yml",
    "database.php", "db.php", "db.php.bak", "appsettings.json", "app.config",
    "web.config", "web.config.bak", "application.yml", "application.properties",
    "application.yaml", "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.override.yml", "dockerfile", "Dockerfile", "docker-compose",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.json", "composer.lock", "requirements.txt", "pyproject.toml",
    "Pipfile", "Pipfile.lock", "Gemfile", "Gemfile.lock", "Procfile",
    "poetry.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml",
    "build.gradle", "gradle.properties", "server.xml", "standalone.xml",
    "jboss-web.xml", "context.xml", "connection.php", "dbconfig.php",
    "global.asa", "web.xml", "application.ini", "system.ini", "php.ini",
    # ---- version control ----
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG", ".git/index",
    ".git/ORIG_HEAD", ".git/packed-refs", ".git/logs/HEAD", ".svn/entries",
    ".svn/wc.db", ".hg/hgrc", ".hg/store", ".bzr/README", ".bzr/branch/branch.conf",
    ".gitignore", ".gitattributes", ".gitmodules", ".DS_Store", ".git/refs/heads/master",
    # ---- keys / credentials ----
    "id_rsa", "id_dsa", ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/authorized_keys",
    ".ssh/config", "private.key", "server.key", "ssl.key", "ssl-cert.key",
    "cert.pem", "key.pem", "private.pem", "server.pem", "fullchain.pem",
    ".htpasswd", ".htaccess", ".credentials", "credentials.json", "key.json",
    "service-account.json", "aws-credentials.json", "secrets.json", "secret.yaml",
    "credential.yml", "token.txt", "api-keys", "apikeys", "oauth.conf",
    # ---- logs / debug ----
    "error.log", "access.log", "debug.log", "app.log", "server.log",
    "php_error.log", "php_errors.log", "application.log", "syslog", "mail.log",
    "auth.log", "cron.log", "npm-debug.log", "yarn-error.log", "celery.log",
    "gunicorn.log", "uwsgi.log", "apache-error.log", "nginx-error.log",
    "exception.log", "trace.log", "phpinfo.php", "info.php", "test.php",
    "debug.php", "status", "status.php", "server-status", "server-info",
    "healthz", "readyz", "alive", "version.php", "whoami", "info",
    # ---- admin / panels ----
    "admin", "admin/", "admin/admin", "admin/login", "admin/panel", "admincp",
    "administrator", "admindb", "adminLogin", "admin-console", "adminarea",
    "bb-admin", "moderator", "webadmin", "control", "controlpanel", "backend",
    "backend/", "panel", "portal", "console", "management", "manager",
    # ---- nested app directories (apps under a sub-folder) ----
    "secret", "secret/", "private", "internal", "intranet", "staging",
    "cms", "blog", "blog/", "shop", "store", "app", "apps", "site", "web",
    "cpanel", "cp", "manager/", "dashboard", "home", "wp-admin/", "wp-admin",
    "wp-login.php", "wp-cron.php", "wp-json/", "phpmyadmin/", "pma",
    "pma/", "myadmin", "mysql-admin", "phpMyAdmin", "user", "users",
    # ---- API / docs ----
    "api", "api/", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
    "api/health", "api/status", "api/user", "api/users", "api/config",
    "swagger", "swagger/", "swagger-ui", "swagger-ui/", "swagger-ui.html",
    "swagger/index.html", "swagger.json", "swagger.yaml", "swagger.yml",
    "openapi.json", "openapi.yaml", "openapi.yml", "api-docs", "api-docs/",
    "redoc", "documentation", "rapidoc", "graphql", "graphiql", "graphql/console",
    "actuator", "actuator/", "actuator/env", "actuator/health", "actuator/dump",
    "actuator/heapdump", "actuator/beans", "actuator/mappings", "actuator/configprops",
    "actuator/metrics", "actuator/loggers", "actuator/threaddump", "actuator/info",
    "metrics", "metrics/", "prometheus", "health", "health/", "ready", "ready/",
    "robots.txt", "sitemap.xml", "sitemap_index.xml", "crossdomain.xml",
    "clientaccesspolicy.xml", "security.txt", ".well-known/security.txt",
    # ---- backups / archives ----
    "backup", "backup/", "backups/", "backup.zip", "backup.tar.gz",
    "backup.tar", "backup.bak", "backup.sql", "backup.db", "backup.txt",
    "db.sql", "db.sql.gz", "db.sqlite", "db.sqlite3", "database.sql",
    "dump.sql", "dump.sql.gz", "data.sql", "data.sql.gz", "full.sql",
    "site.sql", "site.zip", "site.tar.gz", "www.zip", "www.tar.gz",
    "sql.zip", "mysql.sql", "postgres.sql", "local.sql", "bak/", "old",
    "old/", "old-site", "temp", "temp/", "tmp", "tmp/", "cache", "cache/",
    "archive", "archive/", "archives", "archives/", "files", "docs/",
    "uploads/", "upload/", "images", "static/", "media/", "assets/",
    "index.php.bak", "index.bak", "index.html.bak", "index.html.old",
    "config.php.bak", "config.php.old", "settings.bak", "web.config.bak",
    "robots.txt.bak", ".bak", ".old", ".swp", ".swo", "*.~", "~", ".orig",
    "config.sql", "config.db", "db.tar.gz", "db.backup", "dump.db",
    # ---- framework-specific ----
    "vendor/", "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "wp-content/uploads/", "wp-content/debug.log", "wp-includes/",
    "xmlrpc.php", "wp-json/wp/v2/users", "wp-json/", "wp-trackback.php",
    "wp-comments-post.php", "tools", "install.php", "setup.php", "install",
    "setup", "installer.php", "upgrade.php", "update.php", "migrate.php",
    "deploy.php", "maintenance.php", "console.php", "artisan", "bin/console",
    "manage.py", "wsgi.py", "asgi.py", "admin.py", "urls.py", "models.py",
    "seeders/", "migrations/", "migrations/", "trace.axd", "elmah.axd",
    "elmah.axd?resource=about", "phpunit.xml", "phpunit.xml.dist", "phpunit",
    "composer.lock", "package.json", "webpack.config.js", ".babelrc",
    "vite.config.js", "next.config.js", "nuxt.config.js", "gatsby-config.js",
    # ---- auth / sessions / user endpoints ----
    "login", "login/", "login.php", "logout", "signup", "register",
    "register.php", "forgot-password", "reset-password", "profile", "account",
    "my-account", "me", "session", "sessions", "token", "oauth", "oauth2",
    "oauth/token", "auth", "auth/", "authenticate", "authorize", "permissions",
    "admin/login", "backend/login", "api/auth", "signin", "sign-in",
    # ---- frontpage server extensions (CWE-16 legacy FPSE) ----
    "_vti_cnf/", "_vti_bin/", "_vti_bin/_vti_aut/author.dll",
    "_vti_bin/_vti_adm/admin.dll", "_vti_bin/_vti_script/",
    "_vti_pvt/", "_vti_log/", "_vti_txt/", "_vti_inf.html",
    # ---- generic probing ----
    "index.php", "index.html", "index.htm", "home.php", "default.php",
    "default.html", "main.php", "about", "about.html", "contact", "contact.html",
    "readme", "readme.md", "readme.html", "changelog", "license", "licence",
    "LICENSE", "copying", "authors", "contributors", "favicon.ico", "humans.txt",
    "manifest.json", "serviceworker.js", "site.webmanifest", "app.js", "style.css",
    "error", "404", "404.html", "500", "privacy", "privacy.html", "terms",
    "terms.html", "search", "rss", "feed", "atom.xml", "opensearch.xml",
    "security.txt", ".well-known/", "advertise", "news", "blog", "blog/",
    "forum", "forum/", "shop", "cart", "checkout", "payment", "pricing",
    "download", "download/", "downloads", "files/", "doc", "documentation/",
    # ---- classic ASP entry pages (also probed by the ASP error harvester) ----
    "default.asp", "index.asp", "login.asp", "admin.asp", "register.asp",
    "search.asp", "showforum.asp", "templatize.asp",
    # ---- more common webapp paths to reach the 500+ target ----
    "server.php", "server.js", "server.py", "app.py", "routes.py", "views.py",
    "controllers", "controllers/", "services", "services/", "middleware",
    "middleware/", "helpers", "helpers/", "lib", "lib/", "src", "src/",
    "public", "public/", "private", "private/", "uploads", "upload.php",
    "img", "img/", "css", "css/", "js", "js/", "fonts", "fonts/", "vendor",
    "node_modules", "node_modules/", "bower_components", "bower_components/",
    "wp-content", "wp-content/", "wp-admin", "themes", "themes/", "plugins",
    "plugins/", "includes", "includes/", "classes", "classes/", "functions",
    "functions.php", "functions/", "modules", "modules/", "commands", "commands/",
    "jobs", "jobs/", "workers", "workers/", "scheduler", "queues", "broker",
    "config", "config/", "conf", "conf/", "configuration", "settings", "cfg",
    "local", "local/", "prod", "prod/", "stage", "stage/", "live", "live/",
    "benchmark", "test.html", "test/index.html", "test1", "test2", "sample",
    "sample/", "examples", "examples/", "demo", "demo/", "playground", "sandbox",
    "alpha", "beta", "gamma", "rc", "release", "stable", "devel", "dev/",
    "debug.log", "app-debug.log", "server.out", "nohup.out", "stdout.log",
    "stderr.log", "log", "log/", "logs", "logs/", "audit.log", "security.log",
    "php.log", "mysql.log", "postgres.log", "redis.log", "nginx.access.log",
    "tmp.zip", "temp.zip", "data.zip", "data.tar.gz", "files.zip", "backup.7z",
    "dump.7z", "archive.zip", "site.tar", "public_html", "www", "wwwroot",
    "htdocs", "webroot", "uploads.sql", "images/", "userfiles/", "gallery/",
    "media/", "files", "downloads", "attachments", "docs/", "documentation",
    "manual", "guide", "reference", "archive.tar.gz", "old.tar.gz",
    "debug.zip", "logs.zip", "error_log", "core", "core/", "cache.sqlite",
    ".npmrc", ".pypirc", ".dockercfg", ".pgpass", ".netrc", ".ssh",
    "id_ecdsa", "id_ed25519", "hosts", "hostname", "interfaces", "resolv.conf",
]

# Deduplicate while preserving order.
COMMON_PATHS = list(dict.fromkeys(_COMMON_PATHS_SETS))

# Paths whose mere discovery is interesting even without a body.
_SENSITIVE_PATHS = {
    ".env", ".git/config", ".git/HEAD", "wp-config.php", "phpinfo.php",
    "server-status", "actuator/env", "backup.zip", "config.json",
    "swagger-ui.html", "openapi.json", "graphql", "phpmyadmin/",
    "_vti_cnf/", "_vti_bin/", "_vti_bin/_vti_aut/author.dll",
}

# ---------------------------------------------------------------------------
# Soft 404 detection (BUG 2) — the single biggest accuracy fix.
#
# SPA frameworks (React / Next / Vue / Angular) return HTTP 200 on EVERY route
# and serve the same application shell, so a naive scanner reports
# /administrator, /backup, /debug, /server-status etc. as real findings even
# though none of them exist. Before probing any real path we build a profile
# of what a guaranteed-nonexistent path looks like on the target, then suppress
# any finding whose response matches that profile (same body hash, same SPA
# shell, or same error title).
# ---------------------------------------------------------------------------

# Guaranteed-nonexistent paths used to build the 404 fingerprint.
_SOFT_404_PROBE_PATHS = frozenset((
    "/this_does_not_exist_xyz",
    "/zz_not_real_abc123",
    "/nmonesuch_random_404_probe",
))

# Maximum decoded body bytes retained per probe for hashing / keyword checks.
_BODY_SAMPLE = 16 * 1024


@dataclass
class Soft404Profile:
    """Fingerprint of a target's 'not found' / SPA-shell response."""
    typical_status: Optional[int] = None
    typical_length_lo: Optional[int] = None
    typical_length_hi: Optional[int] = None
    body_hashes: set = field(default_factory=set)
    is_spa: bool = False
    not_found_title: Optional[str] = None
    probes_seen: int = 0


def _body_hash(body_text: str) -> str:
    sample = body_text[:_BODY_SAMPLE].encode("utf-8", "replace")
    return hashlib.sha256(sample).hexdigest()


def _build_soft_404_profile(client: httpx.Client, base: str) -> Soft404Profile:
    """Probe guaranteed-nonexistent paths and fingerprint the 404/SPA shell."""
    profile = Soft404Profile()
    statuses: list[int] = []
    lengths: list[int] = []
    titles: set[str] = set()

    for path in sorted(_SOFT_404_PROBE_PATHS):
        try:
            resp = client.get(f"{base}{path}", timeout=PROBE_TIMEOUT)
        except Exception:
            continue
        body = resp.text or ""
        statuses.append(resp.status_code)
        lengths.append(len(body))
        profile.body_hashes.add(_body_hash(body))
        title = _parse_title(body)
        if title:
            titles.add(title)
        profile.probes_seen += 1

    if not profile.probes_seen:
        return profile

    profile.typical_status = max(set(statuses), key=statuses.count)
    lo, hi = min(lengths), max(lengths)
    profile.typical_length_lo = int(lo * 0.8)
    profile.typical_length_hi = int(hi * 1.2)
    if titles:
        profile.not_found_title = sorted(titles, key=len, reverse=True)[0]
    # SPA: all probes returned the 404 probe's typical status AND the bodies
    # are effectively identical (a single shared shell), i.e. hash set size 1
    # with a non-trivial body.
    profile.is_spa = (
        profile.probes_seen == len(_SOFT_404_PROBE_PATHS)
        and len(profile.body_hashes) == 1
        and lo > 0
    )
    return profile


def is_soft_404(status: int, body_text: str, body_len: int,
                title: str, profile: Soft404Profile) -> bool:
    """Return True if a probe response looks like the target's 404/SPA shell."""
    if profile.probes_seen == 0:
        return False

    # 1. Identical body to a known nonexistent-path response.
    if _body_hash(body_text) in profile.body_hashes:
        return True

    # 2. SPA shell: same status + same body-length band as the 404 fingerprint.
    if profile.is_spa and status == profile.typical_status:
        if (profile.typical_length_lo is not None
                and profile.typical_length_hi is not None
                and profile.typical_length_lo <= body_len <= profile.typical_length_hi):
            return True

    # 3. Same page title as the 404 page.
    if profile.not_found_title and title and title == profile.not_found_title:
        return True

    return False


# ---------------------------------------------------------------------------
# Body content validation (BUG 2, step 3).
#
# Even when a path is not a soft 404, a 200 response is only meaningful if the
# body actually contains content expected of that path type. A static file
# server returning the same index.html for every path is not an admin panel.
# Path type -> keywords (at least one must appear in the body to keep the
# finding; otherwise the finding is suppressed or downgraded).
# ---------------------------------------------------------------------------
_BODY_REQUIRED_KEYWORDS = {
    "admin": ["login", "username", "password", "sign in", "dashboard", "admin"],
    "administrator": ["login", "username", "password", "sign in", "dashboard", "admin"],
    "login": ["login", "username", "password", "sign in", "password"],
    "swagger": ["swagger", "openapi", "paths", "definitions", "basePath", "info"],
    "api-docs": ["swagger", "openapi", "paths", "definitions", "basePath", "info"],
    "openapi": ["swagger", "openapi", "paths", "definitions", "basePath", "info"],
    "phpinfo": ["php version", "phpinfo()", "configuration"],
    "graphql": ["graphql", "__schema", "query", "mutation"],
    "graphiql": ["graphql", "__schema", "query", "mutation"],
    "actuator/env": ["activeprofiles", "propertysources", "systemproperties"],
    "env": ["DB_", "APP_", "SECRET", "KEY=", "PASSWORD", "DATABASE_URL"],
    ".env": ["DB_", "APP_", "SECRET", "KEY=", "PASSWORD", "DATABASE_URL"],
    ".git/config": ["[core]", "repositoryformat", "filemode", "[remote"],
    ".git/HEAD": ["ref:", "packed-refs"],
}

# Keywords that always suppress a finding regardless of path — i.e. bodies that
# are clearly a generic server/SPA shell and not the requested resource.
_SUPPRESS_BODY_MARKERS = (
    "<!doctype html", "<!DOCTYPE html", "single page application",
    "creating react app", "you need to enable javascript",
)


def _is_phpinfo_path(low_path: str) -> bool:
    """Check if path is a phpinfo variant."""
    return any(p in low_path for p in ("phpinfo.php", "info.php", "test.php",
                                       "/phpinfo", "/info", "/test"))


def _is_swagger_path(low_path: str) -> bool:
    """Check if path is a swagger/docs variant."""
    return any(p in low_path for p in ("/swagger", "/api-docs", "/docs",
                                        "/swagger-ui", "/redoc"))


def _is_framework_path(low_path: str) -> Optional[str]:
    """Return framework name if path matches a known framework, else None."""
    if ".git/config" in low_path or low_path == ".git/config":
        return "git_config"
    if low_path.startswith(".env") or low_path in ("env", "config.env"):
        return "env_file"
    if low_path.endswith(".sql") or low_path.endswith(".sqlite") or low_path.endswith(".sqlite3"):
        return "sql_file"
    if low_path == "wp-config.php" or low_path.startswith("wp-config"):
        return "wp_config"
    if low_path == "actuator/env":
        return "actuator_env"
    return None


def _body_validation(path: str, body_text: str) -> Optional[str]:
    """Return a validation note if the path's body lacks expected content.

    Returns None when the body passes validation (or the path has no defined
    keyword requirement). Otherwise returns a human-readable note describing
    why the finding is suspect.

    BUG 3 fixes (False Negative suppressions):
      - phpinfo: title "PHP Version" OR body > 50KB → confirmed, no note
      - Swagger UI: "Loading..." title + body > 15KB → confirmed, no note
      - Framework paths: git_config, env_file, sql_file, wp_config,
        actuator_env → confirmed per keywords, no note
      - 403 paths: .htpasswd, .htaccess, server-status → confirmed present,
        note: "exists but access denied (403)"
    """
    low_path = (path or "").lower().lstrip("/")
    body_low = body_text.lower()
    body_len = len(body_text or "")

    # ---- BUG 3 Case 1: phpinfo() ----
    if _is_phpinfo_path(low_path):
        # If title contains "phpinfo()" → confirmed
        if "phpinfo()" in body_low or (re.search(r"<title[^>]*>", body_low, re.I) and "phpinfo" in re.search(r"<title[^>]*>", body_low, re.I).group(0)):
            return None
        # If body contains "PHP Version" AND body > 50KB → confirmed
        if "php version" in body_low and body_len > 50_000:
            return None
        # Otherwise fall through to generic check (will likely flag FP)

    # ---- BUG 3 Case 2: Swagger UI ----
    if _is_swagger_path(low_path):
        # "Loading..." title with body > 15KB → Swagger UI lazy-loads via JS
        title = re.search(r"<title[^>]*>(.*?)</title>", body_low, re.I | re.S)
        if title and "loading" in title.group(1).lower() and body_len > 15_000:
            return None
        # If body contains any swagger marker → confirmed
        swagger_markers = ["swagger", "openapi", "swagger-ui", "redoc",
                           "/openapi.json", "/swagger.json"]
        if any(m in body_low for m in swagger_markers):
            return None

    # ---- BUG 3 Case 3: Framework-specific HIGH confidence paths ----
    framework = _is_framework_path(low_path)
    if framework:
        if framework == "git_config":
            if "[core]" in body_low:
                return None  # CRITICAL confirmed
        elif framework == "env_file":
            # Any KEY=VALUE line means .env is genuinely exposed
            if re.search(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", body_low, re.MULTILINE):
                return None
        elif framework == "sql_file":
            # Body > 100 bytes AND no HTML doctype → genuine SQL dump
            if body_len > 100 and not re.search(r"<!doctype html|<html", body_low):
                return None
        elif framework == "wp_config":
            if "DB_" in body_low:
                return None  # CRITICAL confirmed
        elif framework == "actuator_env":
            if "propertysources" in body_low or "activeprofiles" in body_low:
                return None  # CRITICAL confirmed

    # ---- BUG 3 Case 4: 403 paths ----
    # .htpasswd, .htaccess, server-status at 403: NOT a false positive.
    # 403 = server knows it exists but won't show it.
    four_zero_three_paths = (".htpasswd", ".htaccess", "server-status",
                             "server-info")
    if low_path.lstrip("/") in four_zero_three_paths:
        if "403" in body_low or re.search(r"status.*403", body_low):
            # Return a note that confirms presence, not a FP flag
            return "body_validation: exists but access denied (403) — confirmed present"

    # Keywords that always suppress a finding regardless of path — i.e. bodies that
    # are clearly a generic server/SPA shell and not the requested resource.
    if any(m in body_low for m in _SUPPRESS_BODY_MARKERS):
        return "body_validation: response is a generic application shell — possible false positive"

    # Match the specific keyword set for this path type.
    required = None
    if ".git/config" in low_path:
        required = _BODY_REQUIRED_KEYWORDS[".git/config"]
    elif low_path in _BODY_REQUIRED_KEYWORDS:
        required = _BODY_REQUIRED_KEYWORDS[low_path]
    elif low_path.startswith("wp-config"):
        required = _BODY_REQUIRED_KEYWORDS.get(".env")
    elif low_path.startswith(".env") or low_path in ("env", "config.env"):
        required = _BODY_REQUIRED_KEYWORDS[".env"]
    elif low_path.endswith((".yaml", ".yml", ".json", ".ini", ".conf", ".config")):
        required = _BODY_REQUIRED_KEYWORDS.get(".env")
    elif low_path.startswith(("admin", "administrator")):
        required = _BODY_REQUIRED_KEYWORDS["admin"]
    elif low_path.startswith(("swagger", "api-docs", "openapi")):
        required = _BODY_REQUIRED_KEYWORDS["swagger"]
    elif "graphql" in low_path or "graphiql" in low_path:
        required = _BODY_REQUIRED_KEYWORDS["graphql"]
    elif low_path.startswith("actuator/env"):
        required = _BODY_REQUIRED_KEYWORDS["actuator/env"]
    elif "phpinfo" in low_path or "info.php" in low_path:
        required = _BODY_REQUIRED_KEYWORDS["phpinfo"]

    if not required:
        return None
    if any(k.lower() in body_low for k in required):
        return None
    return ("body_validation: keywords not found — possible false positive"
            f" (expected one of {required[:3]}...)")


# Ordered severity ladder used to downgrade findings that fail body validation.
_SEVERITY_LADDER = ("critical", "high", "medium", "low", "info")


def _downgrade(severity: str) -> Optional[str]:
    """Return the next-lower severity, or None if INFO (caller suppresses).

    critical->high, high->medium, medium->low, low->info, info->None (drop).
    """
    if severity in _SEVERITY_LADDER:
        idx = _SEVERITY_LADDER.index(severity)
        if idx + 1 >= len(_SEVERITY_LADDER):
            return None
        return _SEVERITY_LADDER[idx + 1]
    return severity


def _normalize_base(target: str) -> str:
    target = target.strip()
    if "://" not in target:
        return f"http://{target}"
    return target


def _base_root(base: str) -> str:
    parsed = urlparse(base)
    scheme = parsed.scheme or "http"
    host = parsed.netloc or parsed.hostname or ""
    return f"{scheme}://{host}"


def _parse_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


@base.register
class ContentHttpxScanner(base.Scanner):
    name = "content"
    executable = ""  # pure Python httpx, always available

    def __init__(self) -> None:
        self.warning: Optional[str] = None
        self.detail: Optional[dict] = None
        self._client: Optional[httpx.Client] = None

    def setup_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=PROBE_TIMEOUT,
                # Do not follow redirects: on lab VMs the redirect target is
                # often an internal hostname that does not resolve from the
                # scanner (e.g. Location: http://vtcsec/wp-login.php). Following
                # would raise ConnectError and silently drop the finding. A
                # 3xx on the path is itself the evidence we need.
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT},
                verify=False,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def scan(self, target: str, timeout: int = 120, threads: int = 0) -> List[RawFinding]:
        self.warning = None
        self.detail = None
        base = _base_root(_normalize_base(target))
        concurrency = threads if threads and threads > 0 else PROBE_CONCURRENCY

        paths = list(COMMON_PATHS)
        self.detail = {"paths_tried": len(paths), "base": base, "concurrency": concurrency}

        from pipeline.scanner.content import severity_for_path

        profile = _build_soft_404_profile(self.setup_client(), base)
        probes = self._probe(base, paths, concurrency, profile=profile, detail=self.detail)

        findings: List[RawFinding] = []
        counters = [0, 0, 0]
        self._build_findings(probes, base, target, findings, counters)

        # Bounded sub-directory expansion: apps installed under a sub-folder
        # (e.g. WordPress at /secret/) are invisible to the one-level probe
        # pass, so expand each discovered directory with the WP-specific probe
        # set. Bounded by MAX_SUBDIR_PROBES so the cost stays tiny.
        subprobe_paths = self._subdir_probe_paths(probes)
        if subprobe_paths:
            sub_probes = self._probe(base, subprobe_paths, concurrency,
                                     profile=profile, detail=self.detail)
            self._build_findings(sub_probes, base, target, findings, counters)
            self.detail["subdirs_expanded"] = len(subprobe_paths)

        body_validated, body_downgraded, body_suppressed = counters
        self.detail["body_validation"] = {
            "suspect": body_validated,
            "downgraded": body_downgraded,
            "suppressed": body_suppressed,
        }
        return findings

    def _build_findings(self, probes, base, target, findings, counters) -> None:
        """Convert probe results into RawFindings.

        Handles body-content validation, severity assignment, injectable
        500-on-dynamic-page detection, and the MAX_CONTENT_FINDINGS cap.
        `counters` is a [body_validated, body_downgraded, body_suppressed]
        list mutated in place.
        """
        from pipeline.scanner.content import severity_for_path

        body_validated, body_downgraded, body_suppressed = counters
        for url, info in probes:
            if len(findings) >= MAX_CONTENT_FINDINGS:
                self.detail["truncated"] = True
                break
            path = info.get("path") or url
            body = info.get("body") or ""

            # Body content validation (BUG 2 step 3): a path that responds but
            # whose body carries none of the expected content is suspect.
            note = _body_validation(path, body)
            if note:
                body_validated += 1

            sev = severity_for_path(
                path,
                info.get("status"),
                {"body_length": info.get("content_length"),
                 "title": info.get("title")},
            )

            # Apply body-validation suppression / downgrade.
            if note:
                if sev == "info":
                    body_suppressed += 1
                    continue
                new_sev = _downgrade(sev)
                if new_sev is None:
                    body_suppressed += 1
                    continue
                body_downgraded += 1
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

            if note:
                raw["body_validation"] = note
                description += f" — {note}"

            findings.append(
                RawFinding(
                    scanner="content",
                    scanner_template_id="discovered-path",
                    vulnerability_type="reconnaissance",
                    target=target,
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
                        scanner="content",
                        scanner_template_id="frontpage-extensions",
                        vulnerability_type="frontpage-extensions",
                        target=target,
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

        counters[:] = [body_validated, body_downgraded, body_suppressed]

    def _subdir_probe_paths(self, probes) -> list[str]:
        """Derive the bounded set of sub-paths to expand for nested apps.

        Directories are any probed URL whose final (post-redirect) path is a
        bare directory (no file extension). Each directory is expanded with the
        WP-specific probe set, capped at MAX_SUBDIR_PROBES directories.
        """
        dirs: list[str] = []
        seen: set[str] = set()
        for url, info in probes:
            if len(dirs) >= MAX_SUBDIR_PROBES:
                break
            final = info.get("final_path") or urlparse(url).path or ""
            low = final.strip("/")
            if not low or "/" in low:
                # root directory or already-nested path: only expand one level
                continue
            if "." in low.rsplit("/", 1)[-1] or low in _NON_DIR_PATHS:
                continue
            if low in seen:
                continue
            seen.add(low)
            dirs.append(low)
        paths: list[str] = []
        for d in dirs:
            for sub in _WP_SUBPROBES:
                paths.append(f"{d}/{sub}")
        return paths

    def _probe(self, base: str, paths: list[str], concurrency: int,
               profile: Optional[Soft404Profile] = None,
               detail: Optional[dict] = None) -> list[tuple[str, dict]]:
        client = self.setup_client()
        profile = profile or _build_soft_404_profile(client, base)
        q: Queue = Queue()
        for p in paths:
            q.put(p)
        lock = threading.Lock()
        results: list[tuple[str, dict]] = []
        suppressed = 0

        def worker() -> None:
            nonlocal suppressed
            while True:
                try:
                    path = q.get_nowait()
                except Exception:
                    return
                url = f"{base}/{path}"
                try:
                    resp = client.get(url, timeout=PROBE_TIMEOUT)
                    if not should_emit_finding(path, resp.status_code):
                        continue
                    if resp.status_code not in INTERESTING_STATUS:
                        # A 500 on a server-side dynamic page is a finding even
                        # though it is not in the standard interesting set.
                        if not (resp.status_code == 500 and _is_dynamic_path(path)):
                            continue
                    body = (resp.text or "")[:_BODY_SAMPLE]
                    body_len = len(resp.content) if resp.content else 0
                    title = _parse_title(body)
                    # Soft 404 suppression (BUG 2): a 200 whose body matches the
                    # target's nonexistent-path fingerprint is NOT a real finding.
                    # On a genuine SPA every route serves the same shell, so a
                    # matching body is the shell regardless of which path was
                    # requested — never emit a phantom baseline finding.
                    if is_soft_404(resp.status_code, body, body_len, title, profile):
                        with lock:
                            suppressed += 1
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
                                "final_path": resp.url.path,
                            },
                        ))
                except Exception:
                    # timeouts / connection errors -> not interesting
                    pass
                finally:
                    q.task_done()

        n = min(concurrency, len(paths))
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(n)]
        for t in threads:
            t.start()
        q.join()
        for t in threads:
            t.join()

        # stable ordering by path index
        order = {p: i for i, p in enumerate(paths)}
        results.sort(key=lambda item: order.get(urlparse(item[0]).path, len(paths)))

        if detail is not None:
            detail["soft404_suppressed"] = suppressed
            detail["soft404_profile"] = {
                "typical_status": profile.typical_status,
                "is_spa": profile.is_spa,
                "body_hashes": len(profile.body_hashes),
                "not_found_title": profile.not_found_title,
                "probes_seen": profile.probes_seen,
            }
        return results

    def available(self) -> bool:
        return True