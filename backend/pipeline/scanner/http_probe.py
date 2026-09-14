"""Built-in HTTP probe scanner — lightweight checks with no external deps.

Provides basic web vulnerability/security checks that always run even when
Nmap/Nuclei are absent. It is deliberately conservative: it produces CANDIDATE
findings that still go through the normalizer + active validators.

Checks currently implemented:
    - Missing security headers (clickjacking/X-Frame-Options/CSP/HSTS/etc.)
    - Insecure cookie attributes (missing HttpOnly/Secure/SameSite)
    - Server info leakage (verbose Server / X-Powered-By headers)
    - Technology fingerprinting from headers (tech-stack disclosure)
    - Directory indexing on common paths
    - Common configuration endpoints exposed (~/.env, /.git/config)

Config-endpoint detection is EVIDENCE-BASED: a finding is emitted only when the
response body actually looks like the expected sensitive resource (real
KEY=VALUE env vars, a git repo config, etc.). A 200 on a generic HTML/CDN
error page is classified as a false positive and skipped. Real secret values
are NEVER stored in findings — only key names and evidence metadata.
"""
from __future__ import annotations

import json
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3

from app.models.scanner import RawFinding
from pipeline.scanner import base

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default severity per dedicated P2.2 variant signal (overridden dynamically
# for reflection-based signals).
_VARIANT_SEVERITY = {
    "METHOD_CONFUSION": "low",
    "METHOD_OVERRIDE": "low",
    "IP_SPOOF_RESPONSE": "high",
    "PATH_OVERRIDE_BYPASS": "high",
    "HOST_HEADER_INJECTION": "medium",
    "CACHE_POISONING_PROBE": "medium",
    "HTTP_DOWNGRADE": "low",
    "AUTH_BYPASS_SIGNAL": "low",
    "HEADER_INJECTION_RESPONSE": "low",
    "HTTP_VARIANT_DIFF": "low",
}

# Keywords that, when present in a body diff, immediately raise severity.
_SENSITIVE_LEAK_RE = re.compile(
    r"(password|passwd|token|key|secret|auth|credential|apikey|api[_-]?key)",
    re.I,
)


def _parse_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def _looks_like_json(text: str) -> bool:
    """Best-effort structural JSON detection (object or array)."""
    if not text:
        return False
    stripped = text.strip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False
    try:
        json.loads(stripped[:5000])
        return True
    except Exception:
        # Fallback: accept syntactically plausible JSON prefixes even if
        # truncated/pretty-printed beyond our 5000-char probe window.
        return stripped.startswith("{") and any(
            k in stripped[:2000] for k in ('"', ":")
        ) or stripped.startswith("[") and "]" in stripped[:2000]

SECURITY_HEADERS = (
    "x-frame-options",
    "content-security-policy",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "x-xss-protection",
)

COOKIE_SECURITY_ATTRIBUTES = {
    "httponly": "missing HttpOnly",
    "secure": "missing Secure",
    "samesite": "missing SameSite",
}

COMMON_PATHS = (
    # config / secrets (BUG 2 CRITICAL at 200)
    ".env",
    ".env.local",
    ".env.production",
    ".env.backup",
    "config.php",
    "wp-config.php",
    "settings.py",
    "database.php",
    "db.php",
    ".git/config",
    ".git/HEAD",
    "web.config",
    "config.json",
    "config.ini",
    "config.yaml",
    "appsettings.json",
    # SQL / dump files (BUG 2 CRITICAL at 200)
    "db.sql",
    "database.sql",
    "backup.sql",
    "dump.sql",
    "data.sql",
    "db.sql.gz",
    "db.sqlite",
    "db.sqlite3",
    # private keys / certs (BUG 2 CRITICAL at 200)
    "id_rsa",
    "id_dsa",
    "private.key",
    "server.key",
    "ssl.key",
    "cert.pem",
    ".htpasswd",
    # LOGS (BUG 2 HIGH at 200)
    "error.log",
    "access.log",
    "debug.log",
    "app.log",
    "server.log",
    "php_error.log",
    # admin / debug / docs (BUG 2 HIGH at 200)
    "admin",
    "administrator",
    "phpinfo.php",
    "info.php",
    "actuator/env",
    "actuator/dump",
    "actuator/health",
    "swagger.json",
    "openapi.json",
    "api-docs",
    "swagger-ui.html",
    "swagger/index.html",
    "debug",
    "server-status",
    "server-info",
    # backups (BUG 2 MEDIUM at any status)
    "backup",
    "backup.zip",
    "backup.sql",
    "backup/",
    "uploads/",
    # misc
    "robots.txt",
    "sitemap.xml",
    ".htaccess",
    ".DS_Store",
    "admin/",
    "login",
)

# Technology fingerprints from response headers (name -> (header, needle)).
TECH_HEADER_SIGNATURES = (
    ("nginx", "server", "nginx"),
    ("Apache", "server", "apache"),
    ("IIS", "server", "iis"),
    ("Cloudflare", "server", "cloudflare"),
    ("Varnish", "server", "varnish"),
    ("Fastly", "server", "fastly"),
    ("Akamai", "server", "akamai"),
    ("Netlify", "server", "netlify"),
    ("GitHub Pages", "server", "github"),
    ("PHP", "x-powered-by", "php"),
    ("ASP.NET", "x-powered-by", "asp.net"),
    ("Express", "x-powered-by", "express"),
    ("Django", "server", "gunicorn"),
    ("Flask", "server", "werkzeug"),
    ("Node.js", "x-powered-by", "node"),
    ("Java", "x-powered-by", "java"),
    ("Ruby", "server", "phusion"),
    ("Rails", "server", "passenger"),
)

INDEXING_MARKERS = (
    "index of /",
    "<title>index of",
    "directory listing",
    "parent directory",
)

# Redact a value to a fixed placeholder before it can reach a finding.
_REDACTED = "<redacted>"

# A body that "smells like" a generic page rather than a raw config dump.
_HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body", "cloudflare", "cloudfront")

_ENV_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\r\n]*)", re.MULTILINE)

_PLACEHOLDER_VALUE_RE = re.compile(
    r"(your_|your-|example|xxx+|changeme|change_me|replace_me|todo|dummy|placeholder)"
    r"|^<\w+>$|^\{\{.*\}\}$",
    re.IGNORECASE,
)

_SENSITIVE_KEYS = ("password", "secret", "token", "api_key", "apikey", "private_key",
                   "access_key", "auth", "credentials", "connection_string",
                   "database", "dsn", "db_url", "database_url", "br_token")


@base.register
class HttpProbeScanner(base.Scanner):
    name = "http_probe"
    executable = ""  # always available

    def scan(self, target: str, timeout: int = 10) -> List[RawFinding]:
        """Run lightweight HTTP probes against a target URL.

        Includes parameterized multi-variant comparison (HEAD vs GET, auth
        header, X-Forwarded-For, X-Original-URL path override, and
        Content-Type variants) to surface method-confusion / header-injection
        / auth-bypass signals deterministically (no AI needed).
        """
        url = self._normalize(target)
        findings: List[RawFinding] = []

        try:
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            # If the root isn't reachable, nothing to probe.
            return findings

        findings.extend(self._check_headers(url, resp_headers))
        findings.extend(self._check_cookies(url, resp_headers))
        findings.extend(self._check_tech(url, resp_headers))
        findings.extend(self._check_server_info(url, resp_headers, resp.text))
        findings.extend(self._check_indexing(url, resp.text, timeout))
        findings.extend(self._check_config_paths(url, timeout))
        findings.extend(self._check_variants(url, timeout))

        return findings

    @staticmethod
    def _normalize(target: str) -> str:
        if "://" not in target:
            return f"http://{target}"
        return target

    def _check_headers(self, url: str, headers: dict) -> List[RawFinding]:
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        if not missing:
            return []
        return [
            RawFinding(
                scanner="http_probe",
                scanner_template_id="missing-security-header",
                vulnerability_type="security_header",
                target=url,
                url=url,
                severity="low",
                description=f"missing security header(s): {', '.join(missing)}",
                raw={"missing": missing},
            )
        ]

    def _check_cookies(self, url: str, headers: dict) -> List[RawFinding]:
        """Flag session cookies missing security attributes.

        Looks for Set-Cookie headers and reports cookies that are missing
        HttpOnly, Secure, or SameSite — common session-hijacking / XSS
        hardening gaps.
        """
        raw_cookies = headers.get("set-cookie")
        if not raw_cookies:
            return []
        # Multiple Set-Cookie headers collapse into a comma-joined string;
        # split on a comma that separates cookie blocks (ignore comma inside
        # Expires values is best-effort).
        cookie_blocks = re.split(r",(?=\s*[A-Za-z]+\s*=)", raw_cookies)
        findings: List[RawFinding] = []
        for block in cookie_blocks:
            block = block.strip()
            if not block:
                continue
            name = block.split("=", 1)[0].strip()
            low = block.lower()
            # A cookie name sans value line, e.g. "sessionid"
            missing = [
                attr
                for attr, desc in COOKIE_SECURITY_ATTRIBUTES.items()
                if attr not in low
            ]
            if not missing:
                continue
            findings.append(
                RawFinding(
                    scanner="http_probe",
                    scanner_template_id="insecure-cookie",
                    vulnerability_type="security_header",
                    target=url,
                    url=url,
                    severity="low",
                    description=(
                        f"cookie '{name}' is missing security attribute(s): "
                        + ", ".join(COOKIE_SECURITY_ATTRIBUTES[m] for m in missing)
                    ),
                    raw={"cookie_name": name, "missing": missing, "set_cookie": True},
                )
            )
        return findings

    def _check_tech(self, url: str, headers: dict) -> List[RawFinding]:
        """Fingerprint technology stack from response headers.

        Emits low-severity info findings when a recognizable tech stack is
        disclosed via Server / X-Powered-By / etc., which can guide further
        recon and validation.
        """
        findings: List[RawFinding] = []
        seen = set()
        for tech, header, needle in TECH_HEADER_SIGNATURES:
            value = headers.get(header)
            if not value or tech in seen:
                continue
            if needle.lower() in value.lower():
                seen.add(tech)
                findings.append(
                    RawFinding(
                        scanner="http_probe",
                        scanner_template_id="tech-fingerprint",
                        vulnerability_type="information_disclosure",
                        target=url,
                        url=url,
                        severity="info",
                        description=f"detected technology: {tech} ({value})",
                        raw={"tech": tech, "header": header, "value": value},
                    )
                )
        return findings

    def _check_server_info(self, url: str, headers: dict, body: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        server = headers.get("server")
        powered = headers.get("x-powered-by")
        if server and any(k in server.lower() for k in ("nginx", "apache", "iis", "uvicorn")):
            findings.append(
                RawFinding(
                    scanner="http_probe",
                    scanner_template_id="server-info-leak",
                    vulnerability_type="information_disclosure",
                    target=url,
                    url=url,
                    severity="info",
                    description=f"verbose Server header: {server}",
                    raw={"server": server},
                )
            )
        if powered:
            findings.append(
                RawFinding(
                    scanner="http_probe",
                    scanner_template_id="server-info-leak",
                    vulnerability_type="information_disclosure",
                    target=url,
                    url=url,
                    severity="info",
                    description=f"verbose X-Powered-By header: {powered}",
                    raw={"x_powered_by": powered},
                )
            )
        return findings

    def _check_indexing(self, url: str, body: str, timeout: int) -> List[RawFinding]:
        low = body.lower()
        if any(marker in low for marker in INDEXING_MARKERS):
            return [
                RawFinding(
                    scanner="http_probe",
                    scanner_template_id="directory-indexing",
                    vulnerability_type="information_disclosure",
                    target=url,
                    url=url,
                    severity="medium",
                    description="directory listing/indexing detected",
                    raw={"indexing": True},
                )
            ]
        return []

    def _check_config_paths(self, url: str, timeout: int) -> List[RawFinding]:
        base_url = url.rstrip("/")
        findings: List[RawFinding] = []
        for path in COMMON_PATHS:
            check_url = f"{base_url}/{path}"
            try:
                resp = requests.get(check_url, timeout=max(3, timeout // 2),
                                    verify=False, allow_redirects=False)
            except Exception:
                continue
            classified = self._classify_config(path, resp)
            if classified is None:
                continue
            severity, description, evidence = classified
            findings.append(
                RawFinding(
                    scanner="http_probe",
                    scanner_template_id="exposed-config",
                    vulnerability_type="exposure",
                    target=url,
                    url=check_url,
                    path=path,
                    severity=severity,
                    description=description,
                    raw=evidence,
                )
            )
        return findings

    def _check_variants(self, url: str, timeout: int) -> List[RawFinding]:
        """Send the same request with different method/headers and diff.

        Surfaces AUTH_BYPASS_SIGNAL, HEADER_INJECTION_RESPONSE and
        METHOD_CONFUSION class signals: when tweaking the request changes the
        status/body/length while the intended resource is unchanged, that is a
        strong candidate for a security-relevant behavioral difference.
        Differences are conservative: identical responses are skipped.
        """
        base = self._baseline(url, timeout)
        if base is None:
            return []

        # (name, method, url, headers) — the header/method variants to compare
        # against the baseline. All HEAD-less variants are plain GET unless
        # otherwise specified.
        variants_spec = [
            # BUG 3: HEAD semantics (existing)
            ("method-head", "HEAD", url, {}),
            # Existing broad-signal probes
            ("auth-bearer", "GET", url, {"Authorization": "Bearer invalid"}),
            ("xff-spoof", "GET", url, {
                "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}),
            ("x-original-url-override", "GET", url, {"X-Original-URL": "/admin"}),
            ("content-type-json", "GET", url, {"Content-Type": "application/json"}),
            # P2.2 — method override
            ("method-override", "POST", url, {"X-HTTP-Method-Override": "GET"}),
            # P2.2 — IP spoofing (additional originating-ip headers)
            ("xff-spoof-full", "GET", url, {
                "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1", "Client-IP": "127.0.0.1"}),
            # P2.2 — path override via X-Rewrite-URL
            ("x-rewrite-url-override", "GET", url, {"X-Rewrite-URL": "/admin"}),
            # P2.2 — host header injection
            ("host-header-injection", "GET", url, {"Host": "evil.com"}),
            # P2.2 — cache poisoning probe (X-Forwarded-Host reflection)
            ("cache-poisoning", "GET", url, {"X-Forwarded-Host": "evil.com"}),
        ]

        findings: List[RawFinding] = []
        for name, method, req_url, headers in variants_spec:
            if name == "method-head":
                resp_info = self._head_variant(req_url, timeout)
            else:
                resp_info = self._send(req_url, timeout, headers=headers,
                                       method=method)
            if resp_info is None:
                continue
            diff = self._diff_responses(base, resp_info)
            if not diff or not diff["significant"]:
                continue
            # HOST_HEADER_INJECTION / CACHE_POISONING_PROBE: a status-only
            # diff on a multi-tenant CDN (Netlify, Cloudflare, Vercel) is
            # always a false positive — the CDN returns 404 because "evil.com"
            # isn't a registered tenant.  A real finding requires either:
            #   (a) the injected hostname reflected in the response body, OR
            #   (b) a redirect (Location header) pointing to the injected host.
            if name in ("host-header-injection", "cache-poisoning"):
                variant_body = (resp_info.get("body") or "")
                variant_location = resp_info.get("location") or ""
                body_reflected = "evil.com" in variant_body
                redirect_to_injected = "evil.com" in variant_location.lower()
                if not body_reflected and not redirect_to_injected:
                    continue
            findings.append(self._variant_finding(url, name, name, diff))

        # P2.2 — HTTP downgrade: if the target is HTTPS, probe plain HTTP and
        # check whether it serves content without redirecting to HTTPS.
        findings.extend(self._check_http_downgrade(url, timeout))

        return findings

    def _check_http_downgrade(self, url: str, timeout: int) -> List[RawFinding]:
        """If the target is HTTPS, probe the plain-HTTP variant.

        A server that serves the app over cleartext HTTP without redirecting
        to HTTPS lets an attacker intercept traffic (downgrade). Returns an
        HTTP_DOWNGRADE finding only when a meaningful 2xx page is returned on
        the plain variant.
        """
        if not url.lower().startswith("https://"):
            return []
        http_url = "http://" + url[len("https://"):]
        try:
            resp = requests.get(http_url, timeout=timeout, verify=False,
                                allow_redirects=False)
        except Exception:
            return []
        # If it redirects (e.g. to the https site) or errors out, no downgrade.
        if resp.status_code in (301, 302, 303, 307, 308):
            return []
        if not (200 <= resp.status_code < 400):
            return []
        body = resp.text or ""
        # A real app page (not a blank connection or generic proxy error).
        if len(body) < 50:
            return []
        return [
            RawFinding(
                scanner="http_probe",
                scanner_template_id="HTTP_DOWNGRADE",
                vulnerability_type="http_variant_diff",
                target=url,
                url=http_url,
                severity="low",
                description=(
                    f"plain HTTP endpoint {http_url} serves content "
                    f"(status {resp.status_code}) without redirecting to HTTPS"
                ),
                raw={
                    "http_url": http_url,
                    "https_url": url,
                    "status": resp.status_code,
                    "content_length": len(body),
                },
            )
        ]

    def _baseline(self, url: str, timeout: int) -> Optional[dict]:
        try:
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            return {
                "status": resp.status_code,
                "length": len(resp.content or b""),
                "body": (resp.text or "")[:5000],
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "location": resp.headers.get("location"),
            }
        except Exception:
            return None

    def _send(self, url: str, timeout: int, headers: dict,
              method: str = "GET") -> Optional[dict]:
        try:
            resp = requests.request(method, url, timeout=timeout, verify=False,
                                    allow_redirects=False, headers=headers)
            return {
                "status": resp.status_code,
                "length": len(resp.content or b""),
                "body": (resp.text or "")[:5000],
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "location": resp.headers.get("location"),
            }
        except Exception:
            return None

    def _head_variant(self, url: str, timeout: int) -> dict:
        # HEAD has no body by design; only status + headers are compared.
        try:
            resp = requests.head(url, timeout=timeout, verify=False,
                                 allow_redirects=False)
            return {
                "status": resp.status_code,
                "length": 0,
                "body": "",
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "location": resp.headers.get("location"),
            }
        except Exception:
            return {}

    def _diff_responses(self, base: dict, variant: dict) -> Optional[dict]:
        """Return a diff dict, or None if the variant was not meaningful.

        'significant' is True only when status, or the mirrored location /
        content-length differ materially while the target resource is the same.
        """
        if not variant:
            return None
        status_changed = base["status"] != variant["status"]
        length_delta = abs(variant["length"] - base["length"])
        body_similar = (variant["body"] == base["body"])
        location_changed = (base.get("location") != variant.get("location"))

        # A 401/403-to-200, 404-to-200, or 200-to-403 flip is the strongest signal.
        access_flip = self._access_flip(base["status"], variant["status"])
        diff_excerpt = self._diff_excerpt(base, variant)
        variant_body = variant.get("body") or ""
        if access_flip:
            return {
                "significant": True,
                "signal": access_flip,
                "base_status": base["status"],
                "variant_status": variant["status"],
                "length_delta": length_delta,
                "location_changed": location_changed,
                "reasoning": f"status {base['status']} -> {variant['status']}",
                "diff_excerpt": diff_excerpt,
                "variant_body": variant_body,
            }
        if status_changed:
            return {
                "significant": True,
                "signal": "status-diff",
                "base_status": base["status"],
                "variant_status": variant["status"],
                "length_delta": length_delta,
                "location_changed": location_changed,
                "reasoning": f"status {base['status']} -> {variant['status']}",
                "diff_excerpt": diff_excerpt,
                "variant_body": variant_body,
            }
        if length_delta > max(50, int(base["length"] * 0.1)) and not body_similar:
            return {
                "significant": True,
                "signal": "body-diff",
                "base_status": base["status"],
                "variant_status": variant["status"],
                "length_delta": length_delta,
                "location_changed": location_changed,
                "reasoning": f"body length changed by {length_delta} bytes",
                "diff_excerpt": diff_excerpt,
                "variant_body": variant_body,
            }
        return None

    @staticmethod
    def _diff_excerpt(base: dict, variant: dict, limit: int = 500) -> str:
        """First `limit` chars of the differing body, preferring the longer side.

        For body-less variants (HEAD) the baseline body is the only content
        available, so it is used. Whitespace is collapsed so the stored excerpt
        is compact and greppable.
        """
        base_body = (base.get("body") or "") if isinstance(base.get("body"), str) else ""
        var_body = (variant.get("body") or "") if isinstance(variant.get("body"), str) else ""
        differing = var_body if len(var_body) >= len(base_body) else base_body
        if not differing:
            return ""
        return re.sub(r"\s+", " ", differing).strip()[:limit]

    @staticmethod
    def _access_flip(base_status: int, variant_status: int) -> Optional[str]:
        unauthorized = {401, 403}
        if variant_status == 200 and base_status in unauthorized:
            return "auth-bypass"
        if base_status == 200 and variant_status in unauthorized:
            return "denied-on-variant"
        if base_status in (404, 403, 401) and variant_status in (200, 302):
            return "resource-unlocked"
        return None

    def _variant_finding(self, url: str, name: str, signal: str, diff: dict) -> RawFinding:
        signal_map = {
            "auth-bearer": "AUTH_BYPASS_SIGNAL",
            "xff-spoof": "HEADER_INJECTION_RESPONSE",
            "x-original-url-override": "HEADER_INJECTION_RESPONSE",
            "method-head": "METHOD_CONFUSION",
            "content-type-json": "HEADER_INJECTION_RESPONSE",
            # P2.2 dedicated signals
            "method-override": "METHOD_OVERRIDE",
            "xff-spoof-full": "IP_SPOOF_RESPONSE",
            "x-rewrite-url-override": "PATH_OVERRIDE_BYPASS",
            "host-header-injection": "HOST_HEADER_INJECTION",
            "cache-poisoning": "CACHE_POISONING_PROBE",
        }
        template_id = signal_map.get(name, "HTTP_VARIANT_DIFF")
        signal_desc = diff.get("signal") or ""
        diff_excerpt = diff.get("diff_excerpt") or ""

        severity = _VARIANT_SEVERITY.get(template_id, "low")
        leak_keywords: list[str] = []
        variant_body = diff.get("variant_body") or ""
        reflected_token = self._reflected_token(name, variant_body)
        if template_id == "METHOD_CONFUSION":
            severity, leak_keywords = self._method_confusion_severity(diff_excerpt)
        elif template_id == "HOST_HEADER_INJECTION":
            # Reflection of the injected host in the body is the authoritative
            # signal — treat as confirmed host-header injection. The token is
            # checked against the FULL variant body (not just the truncated
            # diff excerpt), because the reflection can appear anywhere in the
            # response.
            if reflected_token:
                severity = "medium"
        elif template_id == "CACHE_POISONING_PROBE":
            if reflected_token:
                severity = "medium"

        raw = {
            "variant": name,
            "signal": signal,
            "base_status": diff.get("base_status"),
            "variant_status": diff.get("variant_status"),
            "length_delta": diff.get("length_delta"),
            "location_changed": diff.get("location_changed"),
            "reasoning": diff.get("reasoning"),
            "diff_excerpt": diff_excerpt,
        }
        if reflected_token:
            raw["reflected_token"] = reflected_token
        if leak_keywords:
            raw["leak_keywords"] = leak_keywords
            raw["data_leakage_suspected"] = True
        return RawFinding(
            scanner="http_probe",
            scanner_template_id=template_id,
            vulnerability_type="http_variant_diff",
            target=url,
            url=url,
            severity=severity,
            description=(
                f"{name}: response differs from baseline "
                f"({diff.get('reasoning') or signal_desc})"
                + (f"; possible data leakage — keywords: {', '.join(leak_keywords)}"
                   if leak_keywords else "")
            ),
            raw=raw,
        )

    @staticmethod
    def _reflected_token(variant_name: str, variant_body: str) -> Optional[str]:
        """Return the injected token reflected in the variant body, if any.

        Host-header-injection and cache-poisoning probes inject 'evil.com'
        via the Host / X-Forwarded-Host headers. When the server reflects it
        back into the response body, that is authoritative confirmation. The
        token may appear anywhere in the body, so the full (uncapped) variant
        body is searched.
        """
        if variant_name not in ("host-header-injection", "cache-poisoning"):
            return None
        if variant_body and "evil.com" in variant_body:
            return "evil.com"
        return None

    @staticmethod
    def _method_confusion_severity(diff_excerpt: str) -> Tuple[str, list]:
        """Severity boost for METHOD_CONFUSION based on body content.

        - HIGH immediately if the differing body leaks sensitive keywords
          (password, token, key, secret, auth, credential, apikey, api_key).
        - MEDIUM if the differing body is structurally JSON (REST data leak).
        - LOW otherwise.
        Returns (severity, matched_keywords).
        """
        if not diff_excerpt:
            return "low", []
        matched = sorted({m.group(0).lower() for m in _SENSITIVE_LEAK_RE.finditer(diff_excerpt)})
        if matched:
            return "high", matched
        if _looks_like_json(diff_excerpt):
            return "medium", []
        return "low", []

    @staticmethod
    def _classify_config(
        path: str, resp: requests.Response
    ) -> Optional[Tuple[str, str, dict]]:
        """Classify a config-path response by EVIDENCE.

        Returns (severity, description, redacted_evidence) when the response
        genuinely looks like an exposed sensitive resource, else None (skip —
        false positive: 404/403, generic HTML, or harmless placeholder data).

        Values that look like live secrets are never embedded in the evidence;
        only key names and structural metadata are returned.
        """
        status = resp.status_code
        ctype = (resp.headers.get("content-type") or "").lower()
        body = (resp.text or "")[:200_000]

        # Only a successful fetch is evidence of exposure. Redirects and
        # errors are NOT exposure.
        if status != 200:
            return None

        generic_page = any(m in body.lower() for m in _HTML_MARKERS)

        if path == ".env":
            env_vars = _ENV_LINE_RE.findall(body)
            if not env_vars:
                return None
            # A generic template/CDN error page that happens to contain a
            # stray 'KEY=value' pair is not a dump. Require structural bulk.
            if generic_page and len(env_vars) < 2:
                return None
            real_keys, placeholder_keys, sensitive_keys = HttpProbeScanner._env_key_parts(env_vars)
            if not real_keys and not sensitive_keys and not placeholder_keys:
                return None
            if not real_keys and not sensitive_keys:
                # Only placeholder/default values exposed — real but harmless.
                severity = "medium"
            else:
                severity = "high" if sensitive_keys else "medium"
            description = (
                f"exposed /.env with {len(env_vars)} variable(s) "
                f"({len(real_keys)} parsed, {len(sensitive_keys)} sensitive); "
                "values redacted"
            )
            evidence = {
                "status_code": status,
                "content_type": ctype or None,
                "path": path,
                "keys": sorted(real_keys),
                "sensitive_keys": sorted(sensitive_keys),
                "placeholder_keys": sorted(placeholder_keys),
                "values_redacted": True,
            }
            return severity, description, evidence

        if path == ".git/config" and "[core]" in body.lower():
            return "high", "exposed /.git/config (git repository metadata leaked)", {
                "status_code": status,
                "content_type": ctype or None,
                "path": path,
                "values_redacted": True,
            }

        if path in ("config.json", "config.php", "wp-config.php"):
            matched = [k for k in _SENSITIVE_KEYS if k in body.lower()]
            if not matched:
                # No keyword match: fall through so the BUG 2 mapping (which
                # treats these as CRITICAL at 200) can still flag them.
                pass
            else:
                return "high", f"exposed /{path} with sensitive configuration key(s)", {
                    "status_code": status,
                    "content_type": ctype or None,
                    "path": path,
                    "matched_keywords": matched,
                    "values_redacted": True,
                }

        if path == "robots.txt" and ("user-agent" in body.lower() or "disallow" in body.lower()):
            return "info", "robots.txt exposed (disallowed paths disclosed)", {
                "status_code": status,
                "content_type": ctype or None,
                "path": path,
            }

        if path == "sitemap.xml" and "<urlset" in body.lower() or (path == "sitemap.xml" and body.strip().startswith("<")):
            return "info", "sitemap.xml exposed (site structure disclosed)", {
                "status_code": status,
                "content_type": ctype or None,
                "path": path,
            }

        if path in (".htaccess", "web.config") and 200 == status:
            if "[core]" in body.lower() or body.lower().startswith("<ifmodule"):
                return "high", f"exposed /{path} (webserver config leaked)", {
                    "status_code": status,
                    "content_type": ctype or None,
                    "path": path,
                }

        if path in ("phpinfo.php",) and "phpinfo" in body.lower():
            return "high", "exposed /phpinfo.php (PHP configuration disclosure)", {
                "status_code": status,
                "content_type": ctype or None,
                "path": path,
            }

        if path in ("swagger-ui.html", "swagger/index.html", "api-docs", "openapi.json"):
            swagger_markers = ('"swagger"', '"openapi"', "swagger-ui", "openapi", "swagger")
            if any(m in body.lower() for m in swagger_markers):
                return "medium", f"exposed /{path} (API documentation disclosed)", {
                    "status_code": status,
                    "content_type": ctype or None,
                    "path": path,
                }

        if path == "actuator/env" and ("propertySources" in body or "activeProfiles" in body):
            return "high", "exposed /actuator/env (Spring env config disclosure)", {
                "status_code": status,
                "content_type": ctype or None,
                "path": path,
            }

        if path == ".DS_Store":
            return "info", "exposed /.DS_Store (macOS metadata leaked)", {
                "status_code": status,
                "content_type": ctype or None,
                "path": path,
            }

        # BUG 2 fallback: apply the shared severity mapping table for paths that
        # are sensitive by nature (SQL dumps, config files, private keys, logs,
        # admin/debug/docs) even when no deep evidence keyword matched. The
        # mapping table is authoritative for these known-critical paths.
        try:
            from pipeline.scanner.content import severity_for_path
        except Exception:  # noqa: BLE001 - mapping optional
            return None
        mapped = severity_for_path(
            path, status,
            {"body_length": len(body), "title": _parse_title(body)},
        )
        if mapped in ("critical", "high", "medium"):
            # Soft-404 suppression: a sensitive-path mapping on a response
            # whose body is a generic HTML error/landing page (e.g.
            # Apache default 404-as-200, Cloudflare challenge, cPanel
            # placeholder) is unreliable. Downgrade to info or skip
            # rather than reporting a CRITICAL that is really a soft-404.
            generic_page = any(m in body.lower() for m in _HTML_MARKERS)
            if generic_page:
                # Real file dumps (actual .sql, private keys, etc.) are
                # binary or raw text, never well-formed HTML. An HTML
                # response to a dump.sql probe is a generic error page.
                return None
            desc = {
                "critical": f"exposed sensitive file /{path} (served at HTTP {status})",
                "high": f"exposed high-value path /{path} (served at HTTP {status})",
                "medium": f"exposed path /{path} (served at HTTP {status})",
            }[mapped]
            return mapped, desc, {
                "status_code": status,
                "content_type": ctype or None,
                "path": path,
                "severity_source": "severity-mapping (BUG 2)",
            }
        return None

    @staticmethod
    def _env_key_parts(env_vars) -> Tuple[list, list, list]:
        """Split parsed KEY=VALUE pairs into real / placeholder / sensitive."""
        real_keys, placeholder_keys, sensitive_keys = [], [], []
        for key, value in env_vars:
            key = key.strip()
            low_value = value.strip().lower()
            if not value.strip() or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                continue
            if _PLACEHOLDER_VALUE_RE.search(low_value):
                placeholder_keys.append(key)
                continue
            real_keys.append(key)
            if any(s in key.lower() for s in _SENSITIVE_KEYS):
                sensitive_keys.append(key)
        return real_keys, placeholder_keys, sensitive_keys
