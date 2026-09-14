"""Content discovery scanner — feroxbuster.

feroxbuster brute-forces paths on the target using a wordlist. Findings are
emitted for discovered URLs with meaningful HTTP status codes (200, 401/403,
500, 30x with a target). Everything stays BOUNDED: recursion depth and thread
count are capped, and each discovered URL becomes an `info` finding so the
operator has the full map without the scanner wandering into rabbit holes.

Graceful degradation: if feroxbuster or the wordlist is missing, the scanner
reports 'unavailable'/empty rather than failing the pipeline.
"""
from __future__ import annotations

import json
import tempfile
import urllib.parse
from pathlib import Path
from typing import List, Optional

from app.models.scanner import RawFinding
from pipeline.scanner import base

MAX_CONTENT_FINDINGS = 100
INTERESTING_STATUS = {200, 201, 202, 204, 206, 302, 301, 401, 403, 405, 500, 502, 503}

WORDLISTS = (
    Path.home() / ".local" / "share" / "recon" / "common.txt",
    Path("/usr/share/wordlists/dirb/common.txt"),
)


def _find_wordlist() -> Optional[str]:
    for path in WORDLISTS:
        if path.exists():
            return str(path)
    return None


# ---------------------------------------------------------------------------
# Severity scoring for discovered paths (BUG 2).
#
# A discovered path's severity is driven by WHAT the path is and the HTTP
# status code, not merely by the fact that it was found. Exposed pockets of
# sensitive data (SQL dumps, config files, private keys) are CRITICAL, while
# plain 200s are MEDIUM and redirects are LOW. Applied consistently by the
# content scanners (feroxbuster fallback + httpx prober).
# ---------------------------------------------------------------------------

# Extensions that, when served at 200, expose sensitive structured data.
_CRITICAL_EXTENSIONS_200 = (
    ".sql", ".sql.gz", ".dump", ".sqlite", ".sqlite3",
)
# Backup extensions only become CRITICAL when on a config/db filename.
_CRITICAL_BACKUP_EXTENSIONS_200 = (".bak", ".backup", ".old")
# Config / DB filenames generally. Used to qualify backup extensions.
_CONFIG_DB_FILENAME_MARKERS = (
    "config", ".config", "db", "database", "settings", "wp-config",
    "web.config", "appsettings",
)
# Exact paths that are CRITICAL at status 200.
_CRITICAL_EXACT_PATHS_200 = {
    "/config.php", "/wp-config.php", "/settings.py", "/.env",
    "/.env.local", "/.env.production", "/database.php", "/db.php",
    "/.git/config", "/.git/HEAD",
}
# Extensions that are CRITICAL when served at 200 (private keys / certs).
_CRITICAL_PRIVATE_KEY_EXTENSIONS_200 = (".pem", ".key")
_CRITICAL_PRIVATE_KEY_EXACT_200 = {"/id_rsa", "/id_dsa"}

# Dynamic server-side script extensions — an HTTP 500 on one of these is an
# injection-relevant finding rather than a multi-error baseline.
_DYNAMIC_EXTENSIONS = (
    ".asp", ".aspx", ".php", ".jsp", ".jspx", ".cfm",
    ".do", ".action", ".asmx", ".axd",
)

# FrontPage Server Extensions artifacts (CWE-16 / A05 security misconfiguration).
_FRONTPAGE_MARKERS = (
    "_vti_cnf", "_vti_bin", "_vti_pvt", "_vti_log", "_vti_txt",
    "_vti_script", "_vti_inf.html",
)

# HIGH: exact paths at 200, admin panels, debug pages, API docs.
_HIGH_EXACT_PATHS_200 = {
    "/admin", "/admin/", "/administrator", "/phpinfo.php", "/info.php",
    "/actuator/env", "/actuator/dump",
    "/swagger.json", "/openapi.json", "/api-docs",
}
_HIGH_LOG_EXTENSIONS = (".log",)

# MEDIUM: existence distinctly known via 403 on ht files, server-status.
_MEDIUM_EXACT_PATHS_403 = {
    "/.htpasswd", "/.htaccess", "/server-status", "/server-info",
    "/trace.axd", "/elmah.axd", "/glimpse.axd",
}
_MEDIUM_PATHS_ANY_STATUS = {"/backup/", "/uploads/"}

_SENSITIVE_KEYWORDS_RE = None


def _compile_keywords() -> None:
    global _SENSITIVE_KEYWORDS_RE
    if _SENSITIVE_KEYWORDS_RE is None:
        import re
        _SENSITIVE_KEYWORDS_RE = re.compile(
            r"(password|passwd|token|secret|api[_-]?key|private[_-]?key|"
            r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|client[_-]?secret)",
            re.I,
        )


def _path_variants(path: str) -> list[str]:
    """Return plausible URL variants of a path for matching.

    Handles leading-slash differences, trailing slashes, and query/fragment
    stripping. Matches against a set of exact paths.
    """
    if not path:
        return []
    parsed = urllib.parse.urlparse(path)
    only_path = parsed.path or path
    variants = {only_path}
    if not only_path.startswith("/"):
        variants.add("/" + only_path)
    # trailing-slash-tolerant exact matches
    if only_path.endswith("/"):
        variants.add(only_path.rstrip("/"))
    else:
        variants.add(only_path + "/")
    return list(v for v in variants if v)


def _basename_lower(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped.rsplit("/", 1)[-1].lower()


def severity_for_path(path: str, status: int, extra: Optional[dict] = None) -> str:
    """Return a severity for a discovered path + HTTP status.

    Implements the BUG 2 severity mapping table:

      CRITICAL:  sql/backup/private-key exts at 200, exact config/key paths
      HIGH:      admin panels, phpinfo, actuator env, api docs at 200, logs
      MEDIUM:    generic 200s, ht files/server-status at 403, backup dirs
      LOW:       301/302 redirects to interesting paths, generic moved paths
      INFO:      everything else

    `extra` may carry body/content metadata (e.g. title, body length, whether
    the response looks like a Swagger UI page) used for finer decisions.
    """
    extra = extra or {}
    status = int(status)
    variants = _path_variants(path)
    exact = set(variants)
    # also match exact paths against full normalized path list
    norm = [(v.rstrip("/")) for v in exact]
    low_path = (path or "").split("?", 1)[0].split("#", 1)[0].lower()

    # WordPress admin surface — an accessible login is a real attack path.
    # wp-admin at 200 (logged-in/dashboard exposed) is HIGH; any redirect
    # (301/302) to the login page is at least MEDIUM.
    if "wp-admin" in low_path or low_path in ("/wp-admin", "/wp-admin/"):
        if 200 <= status < 300:
            return "high"
        if status in (301, 302, 303, 307, 308):
            return "medium"
        return "medium"

    # WordPress XML-RPC — a known amplification / brute-force surface and the
    # key that unlocks the creds -> RCE correlation chain. Any status counts.
    if "xmlrpc" in low_path:
        return "medium"

    # WordPress core presence — hosting a WP application widens the attack
    # surface (plugins, themes, user enumeration via wp-json). wp-config.php is
    # deliberately excluded: it flows to the CRITICAL classification below.
    if any(m in low_path for m in ("wp-content", "wp-includes", "wp-login.php",
                                   "wp-json", "wp-cron.php")):
        return "high"

    # User-designated application directory (e.g. /secret/) — the operator
    # flagged it; existence at any status is MEDIUM.
    norm_secret = _slash_norm(low_path.rstrip("/"))
    if norm_secret == "/secret" or norm_secret.startswith("/secret/"):
        return "medium"

    # FrontPage Server Extensions artifacts — legacy, known-buggy surface
    # (CWE-16). Existence at any status is MEDIUM.
    if any(m in low_path for m in _FRONTPAGE_MARKERS):
        return "medium"

    # Any-status medium paths (backup / upload dirs) — existence at any code.
    if any(v in _MEDIUM_PATHS_ANY_STATUS for v in variants):
        return "medium"

    # ---- status 200 (or 2xx) ----
    if 200 <= status < 300 or status == 200:
        # exact critical paths (slash-tolerant: match with and without a leading '/')
        if exact & _CRITICAL_EXACT_PATHS_200:
            return "critical"
        if (low_path in _CRITICAL_PRIVATE_KEY_EXACT_200
                or _slash_norm(low_path) in _CRITICAL_PRIVATE_KEY_EXACT_200):
            return "critical"
        # private key / cert extensions
        if _endswith(low_path, _CRITICAL_PRIVATE_KEY_EXTENSIONS_200):
            return "critical"
        # sql / dump / sqlite extensions
        if _endswith(low_path, _CRITICAL_EXTENSIONS_200):
            return "critical"

        # backup extensions on config/db filenames -> critical
        if _endswith(low_path, _CRITICAL_BACKUP_EXTENSIONS_200):
            base = _strip_ext(low_path)
            if any(m in base for m in _CONFIG_DB_FILENAME_MARKERS):
                return "critical"

        # HIGH exact paths (admin / debug / api docs)
        if exact & _HIGH_EXACT_PATHS_200:
            return "high"

        # logs -> high
        if _endswith(low_path, _HIGH_LOG_EXTENSIONS):
            return "high"

        # Swagger UI / docs heuristics: /docs with large body + "Loading"
        doc_low = low_path.rstrip("/")
        if doc_low in ("/docs", "/documentation", "/swagger", "/swagger-ui"):
            body_len = extra.get("body_length") or extra.get("content_length") or 0
            title = (extra.get("title") or "").lower()
            if body_len and body_len > 10_000 and "loading" in title:
                return "high"

        # generic 200 -> medium
        return "medium"

    # ---- 301 / 302 redirects ----
    if status in (301, 302, 303, 307, 308):
        # redirect to an interesting path -> low (still noteworthy)
        if _SENSITIVE_KEYWORDS_RE and _SENSITIVE_KEYWORDS_RE.search(low_path):
            return "low"
        return "low"

    # ---- 5xx: a 500 on a dynamic script is injection-relevant, otherwise noise ----
    if status in (500, 501, 502, 503):
        if _endswith(low_path, _DYNAMIC_EXTENSIONS):
            return "medium"
        return "info"

    # ---- 403 / other non-2xx ----
    if status in (401, 403):
        if exact & _MEDIUM_EXACT_PATHS_403:
            return "medium"
        return "info"

    return "info"


def _endswith(low: str, exts: tuple) -> bool:
    return any(low.endswith(e) for e in exts)


def _strip_ext(low: str) -> str:
    # strip the final extension for backup/old qualification
    if "." not in low:
        return low
    return low.rsplit(".", 1)[0]


def _slash_norm(low: str) -> str:
    """Return the path with a leading slash (for slash-tolerant exact matching)."""
    if not low:
        return low
    return low if low.startswith("/") else "/" + low


_compile_keywords()


@base.register
class ContentScanner(base.Scanner):
    name = "content"
    executable = "feroxbuster"

    def __init__(self) -> None:
        self.warning: Optional[str] = None
        self.detail: Optional[dict] = None

    @property
    def available(self) -> bool:
        from pipeline.scanner.subdomains import resolve_executable
        return bool(resolve_executable("feroxbuster")) and bool(_find_wordlist())

    def scan(self, target: str, timeout: int = 120, depth: int = 2,
             threads: int = 8) -> List[RawFinding]:
        """Brute-force directories/files on a single URL."""
        from pipeline.scanner.subdomains import resolve_executable
        self.warning = None
        self.detail = None

        binary = resolve_executable("feroxbuster")
        wordlist = _find_wordlist()
        if not binary:
            self.warning = "feroxbuster not installed; content discovery unavailable"
            self.detail = {"mode": "unavailable"}
            return []
        if not wordlist:
            self.warning = "no wordlist found; content discovery unavailable"
            self.detail = {"mode": "missing-wordlist"}
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            out_path = tmp.name
        tmp.close()

        cmd = [
            binary, "-u", target, "-w", wordlist,
            "-d", str(depth), "-t", str(threads),
            "-k", "-q", "--json", "-o", out_path,
            "--timeout", "10",
        ]
        try:
            proc = __import__("subprocess").run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
        except __import__("subprocess").TimeoutExpired:
            # feroxbuster is killed, but collected JSON may still be useful
            pass
        except __import__("subprocess").FileNotFoundError:
            self.warning = "feroxbuster binary not found"
            self.detail = {"mode": "unavailable"}
            return []

        findings = self._parse_jsonl(out_path, target)
        Path(out_path).unlink(missing_ok=True)
        self.detail = {
            "wordlist": Path(wordlist).name,
            "depth": depth,
            "threads": threads,
            "found_paths": len(findings),
        }
        return findings

    def _parse_jsonl(self, path: str, target: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        try:
            fp = open(path, encoding="utf-8")
        except OSError:
            return []
        with fp:
            for line in fp:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = rec.get("url")
                if not url:
                    continue
                status = rec.get("status")
                if status not in INTERESTING_STATUS:
                    continue
                sev = severity_for_path(
                    rec.get("url") or "",
                    status,
                    {"content_length": rec.get("content_length"),
                     "content_type": rec.get("content_type")},
                )
                findings.append(
                    RawFinding(
                        scanner="content",
                        scanner_template_id="discovered-path",
                        vulnerability_type="reconnaissance",
                        target=target,
                        host=target,
                        severity=sev,
                        url=url,
                        path=rec.get("url"),
                        description=(
                            f"discovered path: {url} "
                            f"({status}, {rec.get('content_length') or '?'} bytes)"
                        ),
                        raw={
                            "url": url,
                            "status": status,
                            "content_length": rec.get("content_length"),
                            "content_type": rec.get("content_type"),
                        },
                    )
                )
                if any(m in (rec.get("url") or "").lower()
                        for m in _FRONTPAGE_MARKERS):
                    findings.append(
                        RawFinding(
                            scanner="content",
                            scanner_template_id="frontpage-extensions",
                            vulnerability_type="frontpage-extensions",
                            target=target,
                            host=target,
                            severity="medium",
                            url=url,
                            path=rec.get("url"),
                            description=(
                                f"FrontPage Server Extensions directory exposed "
                                f"at {url} — legacy FPSE is a known attack "
                                f"surface (CVE-2000-0386 class)"
                            ),
                            raw={"url": url, "status": status,
                                 "path": rec.get("url")},
                        )
                    )
                if len(findings) >= MAX_CONTENT_FINDINGS:
                    break
        return findings