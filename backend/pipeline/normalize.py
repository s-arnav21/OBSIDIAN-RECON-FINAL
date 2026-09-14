"""Normalizer layer — turn scanner-specific RawFinding into canonical Finding.

Each canonical `Finding` carries:
  - a single `vulnerability_type` (normalised from scanner aliases)
  - resolved `validator_id` and CWE/OWASP class + remediation guidance
  - a `validation` state (confirmed / rejected / manual-review / error)
  - the `evidence` map keyed by evidence_id.

The normalizer is deliberately deterministic: alias and KB lookups are constant
maps, so the same RawFinding always yields the same Finding (stable for tests
and for cache/repeat runs).
"""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlparse

from app.models.finding import Finding
from app.models.scanner import RawFinding
from app.models.validation import ValidationResult, ValidationStatus


def _norm_identity(raw: RawFinding, asset_id: str) -> str:
    """A non-empty target/host identity for a raw finding.

    Scanner rows occasionally omit target/host entirely (notably nmap -cS
    script rows such as ssl-cert / http-title), and Finding requires both
    fields to be non-empty. Fall back to the observed URL's host, then to
    the asset id, then to a placeholder so normalization never raises.
    """
    for candidate in (raw.target, raw.host):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    for url in (raw.matched_at, raw.url):
        if isinstance(url, str) and url.strip():
            try:
                host = urlparse(url).hostname
                if host:
                    return host
            except ValueError:
                pass
            return url.strip()
    return asset_id or "?"


# --------------------------------------------------------------------------
# vulnerability-type aliases → canonical type
# --------------------------------------------------------------------------
# Slugs as emitted by scanners/skills map onto KB canonical keys. Any slug the
# map does not cover is lower-cased and underscores are replaced by dashes
# (so nuclei "sql_injection" and skills "sqli" both land on one canonical key).
_ALIASES = {
    # open services / ports
    "open-port": "open-service-exposure",
    "port-open": "open-service-exposure",
    "service-exposed": "open-service-exposure",
    "service-detected": "open-service-exposure",
    "open-service": "open-service-exposure",
    # TLS
    "weak-cipher": "weak-tls-cipher",
    "ssl-weak": "weak-tls-cipher",
    "tls-weak": "weak-tls-cipher",
    "tls-weak-cipher": "weak-tls-cipher",
    "expired-cert": "expired-tls",
    "self-signed-cert": "expired-tls",
    # headers / web misconfig
    "missing-header": "missing-security-header",
    "csp-missing": "missing-security-header",
    "x-frame-options-missing": "clickjacking",
    "clickjacking-detect": "clickjacking",
    "cookie": "cookie-missing-httponly",
    "insecure-cookie": "cookie-missing-httponly",
    "cookie-missing-httponly-flag": "cookie-missing-httponly",
    "waf-bypass": "waf-origin",
    "origin-exposed": "waf-origin",
    "waf-detected": "waf-presence",
    "wp-user-enum": "user-enumeration",
    "user-exposure": "user-enumeration",
    "user-enum": "user-enumeration",
    "backup": "sensitive-backup-file",
    "sensitive-backup": "sensitive-backup-file",
    "debug-page": "debug-mode-exposed",
    "debug": "debug-mode-exposed",
    "info-leak": "information-disclosure",
    "leaked-san": "information-disclosure",
    "exposure": "exposure",
    "exposed-config": "exposure",
    "exposed-sensitive-file": "exposure",
    "exposed-env": "env-exposed",
    "dotenv-exposed": "env-exposed",
    "env-file": "env-exposed",
    "git-exposed": "git-exposed",
    "git-file": "git-exposed",
    "discovered-path": "discovered-path",
    # injection / web-exploit families
    "sql": "sql-injection",
    "sqli": "sql-injection",
    "sql-injection": "sql-injection",
    "sqli-error": "sql-injection",
    "sqli-error-signal": "sql-injection",
    "sqli-blind": "sql-injection",
    "sqli-time": "sql-injection",
    "sqli-boolean": "sql-injection",
    "sqli-union": "sql-injection",
    "sqli-stacked": "sql-injection",
    "rce": "command-execution",
    "command_injection": "command-execution",
    "command-injection": "command-execution",
    "remote-code-execution": "command-execution",
    "remote_code_execution": "command-execution",
    "os-command-injection": "command-execution",
    "os-injection": "command-execution",
    "shell": "command-execution",
    "webshell": "command-execution",
    "file-upload": "file-upload",
    "unrestricted-file-upload": "file-upload",
    "xss": "xss",
    "reflected-xss": "xss",
    "reflected_xss": "xss",
    "stored-xss": "xss",
    "stored_xss": "xss",
    "dom-xss": "xss",
    "cross-site-scripting": "xss",
    "lfi": "lfi",
    "local-file-inclusion": "lfi",
    "path-traversal": "lfi",
    "path_traversal": "lfi",
    "path-traversal-lfi": "lfi",
    "xxe": "xxe",
    "xml-external-entity": "xxe",
    "external-entity": "xxe",
    "ssrf": "ssrf",
    "server-side-request-forgery": "ssrf",
    "csrf": "csrf",
    "cross-site-request-forgery": "csrf",
    "ssti": "ssti",
    "server-side-template-injection": "ssti",
    "template-injection": "ssti",
    "idor": "idor",
    "insecure-direct-object-reference": "idor",
    "open-redirect": "open-redirect",
    "open_redirect": "open-redirect",
    "unvalidated-redirect": "open-redirect",
    "unvalidated_redirect": "open-redirect",
    "host-header-injection": "host-header-injection",
    "host_header_injection": "host-header-injection",
    "host-header": "host-header-injection",
    # authentication / access
    "default-login": "default-credentials",
    "default-login-cred": "default-credentials",
    "default_credentials": "default-credentials",
    "default-creds": "default-credentials",
    "weak-credentials": "weak-credentials",
    "weak_credentials": "weak-credentials",
    "weak-password": "weak-credentials",
    "brute-force": "weak-credentials",
    "exposed-admin-panel": "exposed-admin-panel",
    "admin-panel-exposed": "exposed-admin-panel",
    "admin-login-exposed": "exposed-admin-panel",
    # crypto / authn
    "weak-hashing": "weak-hashing",
    "weak-hash": "weak-hashing",
    "md5-hash": "weak-hashing",
    "sha1-hash": "weak-hashing",
    # infra
    "subdomain-takeover": "subdomain-takeover",
    "takeover": "subdomain-takeover",
    "tech-fingerprint": "reconnaissance",
    "technology-identified": "reconnaissance",
    "server-info-leak": "information-disclosure",
    "cve": "cve",
    "unknown-cve": "cve",
    "nuclei-candidate": "cve",
}


def _canonical_type(raw: RawFinding) -> str:
    base = (raw.vulnerability_type or raw.scanner_template_id or "unknown").lower()
    if base in _ALIASES:
        return _ALIASES[base]
    return base.replace("_", "-")


# --------------------------------------------------------------------------
# CWE / OWASP / MITRE / CVSS / remediation knowledge per canonical type
# --------------------------------------------------------------------------
# `label` is the human-readable summary heading (used by the severity-summary
# UI instead of raw slugs); `mitre` is the primary ATT&CK technique id;
# `severity` is the KB-baseline severity for the assigned CVSS base score.
_KB: dict[str, dict] = {
    # ——— open services & network exposure ———
    "open-service-exposure": {
        "label": "Open service exposure",
        "cwe": "CWE-284", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1046", "cvss": 5.6, "severity": "medium",
        "remediation": ("Restrict exposed service to trusted networks / auth; "
                        "close unnecessary ports; isolate via firewall rules."),
    },
    "weak-tls-cipher": {
        "label": "Weak TLS cipher or protocol",
        "cwe": "CWE-295", "owasp": "A02 Cryptographic Failures",
        "mitre": "T1573", "cvss": 7.4, "severity": "high",
        "remediation": ("Disable weak ciphers/protocols; enforce TLS1.2+ with a "
                        "strong cipher suite; align ciphers with Mozilla baseline."),
    },
    "expired-tls": {
        "label": "Expired TLS certificate",
        "cwe": "CWE-299", "owasp": "A02 Cryptographic Failures",
        "mitre": "T1592", "cvss": 6.5, "severity": "medium",
        "remediation": ("Renew the TLS/domain certificate and automate expiry "
                        "monitoring and re-issuance."),
    },
    # ——— web misconfiguration & hardening ———
    "missing-security-header": {
        "label": "Missing security header",
        "cwe": "CWE-693", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1190", "cvss": 3.7, "severity": "low",
        "remediation": ("Set security headers (CSP, HSTS, X-Content-Type-Options, "
                        "Permissions-Policy) and enforce via server middleware."),
    },
    "clickjacking": {
        "label": "Clickjacking (frameable page)",
        "cwe": "CWE-1021", "owasp": "A04 Insecure Design",
        "mitre": "T1204", "cvss": 4.3, "severity": "medium",
        "remediation": ("Send Content-Security-Policy: frame-ancestors 'none' "
                        "and/or X-Frame-Options: DENY."),
    },
    "cookie-missing-secure": {
        "label": "Cookie without Secure flag",
        "cwe": "CWE-614", "owasp": "A07 Identification and Authentication Failures",
        "mitre": "T1539", "cvss": 4.3, "severity": "medium",
        "remediation": "Mark all auth cookies Secure + HttpOnly; use SameSite."
    },
    "cookie-missing-httponly": {
        "label": "Cookie without HttpOnly flag",
        "cwe": "CWE-1004", "owasp": "A07 Identification and Authentication Failures",
        "mitre": "T1539", "cvss": 4.3, "severity": "medium",
        "remediation": "Set HttpOnly on all non-XHR cookies.",
    },
    "mime-sniffing": {
        "label": "MIME sniffing allowed",
        "cwe": "CWE-79", "owasp": "A08 Software and Data Integrity Failures",
        "mitre": "T1189", "cvss": 4.3, "severity": "medium",
        "remediation": "Send X-Content-Type-Options: nosniff.",
    },
    "waf-presence": {
        "label": "WAF/CDN detected",
        "cwe": "CWE-693", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1590", "cvss": 3.1, "severity": "info",
        "remediation": ("Verify origin exhaustion: pin origins to the CDN/WAF, "
                        "block direct access to origin IPs, monitor for leaks."),
    },
    "waf-origin": {
        "label": "WAF origin IP exposed",
        "cwe": "CWE-200", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1590", "cvss": 7.5, "severity": "high",
        "remediation": ("Hide origin IP: allow only CDN/WAF IP ranges on origin "
                        "firewall; disable direct IP access; rotate A records."),
    },
    "sensitive-backup-file": {
        "label": "Sensitive backup or archive exposed",
        "cwe": "CWE-530", "owasp": "A01 Broken Access Control",
        "mitre": "T1083", "cvss": 7.5, "severity": "high",
        "remediation": ("Remove backup/asset files from the web root; block "
                        "archive extensions (bak~, .zip, .sql) at the web server."),
    },
    "debug-mode-exposed": {
        "label": "Debug interface exposed",
        "cwe": "CWE-489", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1083", "cvss": 5.3, "severity": "medium",
        "remediation": "Disable debug panels in production; restrict to trusted IPs."
    },
    "exposure": {
        "label": "Sensitive content exposed",
        "cwe": "CWE-538", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1083", "cvss": 6.5, "severity": "medium",
        "remediation": ("Gate sensitive/config endpoints behind auth; remove "
                        "unnecessary files from the web root; block directory "
                        "listing."),
    },
    "env-exposed": {
        "label": "Environment / .env file exposed",
        "cwe": "CWE-538", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1083", "cvss": 9.1, "severity": "critical",
        "remediation": ("Remove .env from the web root; rotate every credential "
                        "the file contains; block dot-file access in the web "
                        "server config."),
    },
    "git-exposed": {
        "label": ".git directory exposed",
        "cwe": "CWE-538", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1083", "cvss": 7.5, "severity": "high",
        "remediation": ("Remove .git from production; block .git paths at the "
                        "web server / reverse proxy."),
    },
    "discovered-path": {
        "label": "Sensitive path discovered",
        "cwe": "CWE-538", "owasp": "A01 Broken Access Control",
        "mitre": "T1083", "cvss": 5.3, "severity": "medium",
        "remediation": ("Gate sensitive/archive paths behind auth; remove "
                        "unnecessary files from the web root; block directory "
                        "listing and access to secret/config endpoints."),
    },
    "frontpage-extensions": {
        "label": "FrontPage Server Extensions enabled",
        "cwe": "CWE-16", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1190", "cvss": 6.5, "severity": "medium",
        "remediation": ("Remove FrontPage Server Extensions (FPSE) from the web "
                        "server; disable the _vti_ directories; FPSE is a "
                        "legacy, bug-prone extension (CVE-2000-0386 class) with "
                        "published authoring/exploit vectors."),
    },
    "exposed-admin-panel": {
        "label": "Admin panel exposed",
        "cwe": "CWE-284", "owasp": "A07 Identification and Authentication Failures",
        "mitre": "T1190", "cvss": 6.5, "severity": "medium",
        "remediation": ("Move admin panels behind VPN/IP allow-lists; enforce "
                        "MFA; rate-limit login attempts."),
    },
    "user-enumeration": {
        "label": "Username enumeration",
        "cwe": "CWE-204", "owasp": "A07 Identification and Authentication Failures",
        "mitre": "T1589", "cvss": 5.3, "severity": "medium",
        "remediation": ("Return identical responses for valid/invalid identities; "
                        "rate-limit auth endpoints; remove banner user enumeration."),
    },
    "information-disclosure": {
        "label": "Information disclosure",
        "cwe": "CWE-200", "owasp": "A01 Broken Access Control",
        "mitre": "T1592", "cvss": 5.3, "severity": "medium",
        "remediation": "Strip server/version banners and error detail in prod."
    },
    "misconfiguration": {
        "label": "Security misconfiguration",
        "cwe": "CWE-693", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1592", "cvss": 5.3, "severity": "medium",
        "remediation": "Review default settings, enabled components and headers against a hardening baseline."
    },
    "reconnaissance": {
        "label": "Reconnaissance / enumeration result",
        "cwe": "CWE-200", "owasp": "A01 Broken Access Control",
        "mitre": "T1590", "cvss": 0.0, "severity": "info",
        "remediation": ("Review exposure from passive enumeration; hide internal "
                        "hostnames; remove historical artifacts."),
    },
    "subdomain-takeover": {
        "label": "Subdomain takeover",
        "cwe": "CWE-428", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1584", "cvss": 7.5, "severity": "high",
        "remediation": ("Remove dangling DNS CNAMEs; claim/release external "
                        "services; monitor liveness of host records."),
    },
    # ——— injection (OWASP A03) ———
    "sql-injection": {
        "label": "SQL injection",
        "cwe": "CWE-89", "owasp": "A03 Injection",
        "mitre": "T1190", "cvss": 9.8, "severity": "critical",
        "remediation": ("Use parameterized queries / prepared statements; apply "
                        "least privilege to the DB account; validate and sanitize "
                        "all input; review ORM usage for raw SQL."),
    },
    "lfi": {
        "label": "Local file inclusion / path traversal",
        "cwe": "CWE-22", "owasp": "A01 Broken Access Control",
        "mitre": "T1083", "cvss": 8.6, "severity": "high",
        "remediation": ("Validate + whitelist file/stream names; chroot or "
                        "virtual-path jail the filesystem; never mirror user "
                        "input into filesystem paths."),
    },
    "xss": {
        "label": "Cross-site scripting (XSS)",
        "cwe": "CWE-79", "owasp": "A03 Injection",
        "mitre": "T1189", "cvss": 6.1, "severity": "medium",
        "remediation": ("Encode output contextually; set a strict CSP; validate "
                        "and sanitize all user input before rendering."),
    },
    "xxe": {
        "label": "XML external entity (XXE)",
        "cwe": "CWE-611", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1190", "cvss": 8.8, "severity": "high",
        "remediation": ("Disable DTD / external entity processing in the XML "
                        "parser; prefer JSON/serialisation formats."),
    },
    "ssrf": {
        "label": "Server-side request forgery (SSRF)",
        "cwe": "CWE-918", "owasp": "A10 SSRF",
        "mitre": "T1190", "cvss": 9.1, "severity": "critical",
        "remediation": ("Validate and allow-list destinations; block redirects "
                        "to internal ranges/metadata IPs; apply egress filtering."),
    },
    "ssti": {
        "label": "Server-side template injection",
        "cwe": "CWE-1336", "owasp": "A03 Injection",
        "mitre": "T1059", "cvss": 9.8, "severity": "critical",
        "remediation": ("Never concatenate raw user input into templates; use "
                        "sandboxed, logic-less template engines."),
    },
    "csrf": {
        "label": "Cross-site request forgery (CSRF)",
        "cwe": "CWE-352", "owasp": "A01 Broken Access Control",
        "mitre": "T1204", "cvss": 6.5, "severity": "medium",
        "remediation": ("SameSite cookies for state-changing requests; anti-CSRF "
                        "tokens bound to the session; double-submit cookie."),
    },
    "idor": {
        "label": "Insecure direct object reference (IDOR)",
        "cwe": "CWE-639", "owasp": "A01 Broken Access Control",
        "mitre": "T1530", "cvss": 6.5, "severity": "medium",
        "remediation": ("Enforce object-level authorization on every read/write; "
                        "use unguessable, signed resource identifiers."),
    },
    "command-execution": {
        "label": "Command / RCE injection",
        "cwe": "CWE-78", "owasp": "A03 Injection",
        "mitre": "T1059", "cvss": 9.8, "severity": "critical",
        "remediation": ("Never shell out with user input; use argument arrays "
                        "and allow-lists; sandbox subprocesses."),
    },
    "file-upload": {
        "label": "Unrestricted file upload",
        "cwe": "CWE-434", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1505", "cvss": 9.8, "severity": "critical",
        "remediation": ("Validate content/magic bytes; serve uploads from a "
                        "sandboxed, non-executable origin; scan + quarantine."),
    },
    "host-header-injection": {
        "label": "Host header injection",
        "cwe": "CWE-290", "owasp": "A07 Identification and Authentication Failures",
        "mitre": "T1190", "cvss": 6.1, "severity": "medium",
        "remediation": ("Validate the Host header against an allow-list; ignore "
                        "X-Forwarded-Host on external-facing servers."),
    },
    "open-redirect": {
        "label": "Open redirect",
        "cwe": "CWE-601", "owasp": "A01 Broken Access Control",
        "mitre": "T1566", "cvss": 4.3, "severity": "medium",
        "remediation": ("Whitelist redirect destinations; reject relative-to-absolute "
                        "external paths; encode output."),
    },
    "default-credentials": {
        "label": "Default credentials in use",
        "cwe": "CWE-284", "owasp": "A07 Identification and Authentication Failures",
        "mitre": "T1078", "cvss": 9.8, "severity": "critical",
        "remediation": ("Rotate every default vendor credential; enforce unique "
                        "strong passwords and MFA on all accounts."),
    },
    "weak-credentials": {
        "label": "Brute-forceable / weak credentials",
        "cwe": "CWE-307", "owasp": "A07 Identification and Authentication Failures",
        "mitre": "T1110", "cvss": 7.5, "severity": "high",
        "remediation": ("Enforce account lockout + rate limiting; require strong "
                        "passwords; deploy MFA."),
    },
    "weak-hashing": {
        "label": "Weak cryptographic hashing",
        "cwe": "CWE-327", "owasp": "A02 Cryptographic Failures",
        "mitre": "T1555", "cvss": 7.5, "severity": "high",
        "remediation": ("Replace MD5/SHA1 for password storage with Argon2id / "
                        "bcrypt / scrypt with per-record salts."),
    },
    "cve": {
        "label": "Known-vulnerable component (CVE)",
        "cwe": "CWE-1035", "owasp": "A06 Vulnerable and Outdated Components",
        "mitre": "T1190", "cvss": 9.8, "severity": "critical",
        "remediation": ("Upgrade/patch the affected component; if unavailable, "
                        "apply vendor workaround and compensating controls."),
    },
    # ——— OSINT / asset-intelligence (recon skills) ———
    "osint-cert-expired": {
        "label": "Domain certificate expired",
        "cwe": "CWE-299", "owasp": "A02 Cryptographic Failures",
        "mitre": "T1590", "cvss": 6.5, "severity": "medium",
        "remediation": ("Renew the domain registration immediately; verify DNS "
                        "and email routes; set renewal + expiry automation."),
    },
    "osint-domain-expiring": {
        "label": "Domain expiring soon",
        "cwe": "CWE-404", "owasp": "A05 Security Misconfiguration",
        "mitre": "T1583", "cvss": 3.1, "severity": "low",
        "remediation": ("Renew the domain before the <90-day expiry window; "
                        "enable auto-renewal and monitor WHOIS expiry."),
    },
    "osint-internal-san": {
        "label": "Internal hostname in certificate SANs",
        "cwe": "CWE-200", "owasp": "A01 Broken Access Control",
        "mitre": "T1590", "cvss": 3.7, "severity": "low",
        "remediation": ("Remove internal hostnames / IPs from public-issued "
                        "certificate SANs; use internal-only CAs for private "
                        "names."),
    },
    "osint-ip-in-cert-san": {
        "label": "IP literal in certificate SANs",
        "cwe": "CWE-200", "owasp": "A01 Broken Access Control",
        "mitre": "T1590", "cvss": 3.1, "severity": "low",
        "remediation": ("Remove IP literals from publicly issued certificate "
                        "SANs to reduce enumerate-able attack surface."),
    },
    "osint-historical-sensitive-path": {
        "label": "Historical sensitive path archived",
        "cwe": "CWE-538", "owasp": "A01 Broken Access Control",
        "mitre": "T1593", "cvss": 5.3, "severity": "low",
        "remediation": ("Purge archived sensitive paths; re-evaluate whether "
                        "historical disclosures expose secrets; rotate exposed "
                        "credentials."),
    },
    "osint-shared-hosting-detected": {
        "label": "Shared hosting detected",
        "cwe": "CWE-200", "owasp": "A01 Broken Access Control",
        "mitre": "T1590", "cvss": 2.4, "severity": "info",
        "remediation": ("Confirm third-party hosting provider and its security "
                        "posture; isolate directories; monitor co-tenancy risk."),
    },
    "unknown": {
        "label": "Unclassified finding",
        "cwe": "CWE-710", "owasp": "A04 Insecure Design",
        "mitre": "T1059", "cvss": 0.0, "severity": "unknown",
        "remediation": "Manual review required.",
    },
}

_DEFAULT_KB = _KB["unknown"]

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def _kb_for(canonical: str) -> dict:
    return _KB.get(canonical, _DEFAULT_KB)


def cvss_severity(score: float) -> str:
    """Severity label for a CVSS base score (v3 rating scale)."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    if score == 0.0:
        return "info"
    return "unknown"


def severity_for_type(canonical: str, raw_severity: str = "unknown") -> str:
    """KB-driven severity for a canonical vulnerability type.

    Returns the more severe of (tool-reported severity, KB baseline severity
    derived from the KB CVSS score). Generic types like reconnaissance/
    misconfiguration that carry no CVSS fall back to the tool's rating, so a
    `high`-rated nuclei hit is never downgraded by the KB default.
    """
    kb = _kb_for(canonical)
    kb_sev = cvss_severity(float(kb.get("cvss", 0.0)) or 0.0)
    tool_sev = str(raw_severity or "unknown").lower()
    if tool_sev not in _SEV_RANK:
        tool_sev = "unknown"
    if _SEV_RANK.get(kb_sev, 0) >= _SEV_RANK.get(tool_sev, 0):
        return kb_sev
    return tool_sev


# --------------------------------------------------------------------------
# validator_id resolution
# --------------------------------------------------------------------------


def _validator_for(canonical: str) -> str:
    canon = canonical.replace("-", "_")
    return f"validate_{canon}" if canon not in ("unknown", "reconnaissance") else "validate_manual"


def _endpoint_from(raw: RawFinding) -> Optional[str]:
    for candidate in (raw.matched_at, raw.url):
        if candidate and "://" in candidate:
            return candidate
    return None


def normalize_all(
    findings: List[RawFinding],
    scan_id: str,
    asset_id: str = "",
    validation: Optional[dict[str, ValidationResult]] = None,
    evidence_lookup: Optional[dict[str, dict]] = None,
) -> List[Finding]:
    """Convert a list of RawFinding into canonical Finding objects.

    Args:
        findings: raw scanner findings.
        scan_id: id of the enclosing scan.
        asset_id: id of the target asset (optional).
        validation: optional mapping from validator._fp_key → ValidationResult.
        evidence_lookup: optional mapping from evidence_id → Evidence.to_dict().

    Returns:
        Cleaned, deduplicated canonical Finding list (one per unique raw row).
    """
    validation = validation or {}
    evidence_lookup = evidence_lookup or {}
    canonical: List[Finding] = []
    seen: set = set()

    for i, raw in enumerate(findings):
        key = (raw.scanner, raw.scanner_template_id, _endpoint_from(raw) or raw.host or "")
        if key in seen:
            continue
        seen.add(key)

        vtype = _canonical_type(raw)
        kb = _kb_for(vtype)

        ev_ids = getattr(raw, "evidence_id", None) or (
    raw.raw.get("evidence_id") if isinstance(raw.raw, dict) else None)
        evidence = {}
        if ev_ids:
            ev_ids = ev_ids if isinstance(ev_ids, list) else [ev_ids]
            evidence = {eid: evidence_lookup.get(eid, {}) for eid in ev_ids if eid in evidence_lookup}
        if not evidence:
            evidence = dict(raw.raw or {})

        self_id = f"F{scan_id}-{i:04d}"
        identity_host = _norm_identity(raw, asset_id)
        vr = validation.get(
            _fp_key_like(raw, identity_host),
            ValidationResult(
                status="manual_review",
                confidence=0.0,
                validator="structural-recon",
                method="structural",
            ),
        )
        canonical.append(Finding(
            finding_id=self_id,
            scan_id=scan_id,
            asset_id=asset_id,
            target=identity_host,
            host=identity_host,
            source=raw.scanner,
            vulnerability_type=vtype,
            template_id=raw.scanner_template_id,
            validator_id=vr.validator or (kb.get("validator_id") or _validator_for(vtype)),
            endpoint=_endpoint_from(raw),
            severity=severity_for_type(vtype, raw.severity),
            validation_status=vr.status,
            validation_confidence=vr.confidence,
            evidence=evidence,
            evidence_refs=list(getattr(vr, "evidence_refs", []) or []),
            raw_finding_ref=None,
        ))
    return canonical


def _fp_key_like(f: RawFinding, target: str) -> str:
    host = (f.matched_at or f.url or f.host or f.target or "?")
    return f"{f.scanner}:{f.scanner_template_id}:{host}"


def enrich(finding: Finding) -> dict:
    """Return the CWE/OWASP/CVSS/MITRE/remediation knowledge for a normalized Finding."""
    kb = _kb_for(finding.vulnerability_type)
    return {
        "label": kb["label"],
        "cwe": kb["cwe"],
        "owasp": kb["owasp"],
        "mitre": kb.get("mitre", ""),
        "cvss": kb.get("cvss", 0.0),
        "severity": severity_for_type(finding.vulnerability_type, finding.severity),
        "remediation": kb["remediation"],
    }


def label_for(canonical: str) -> str:
    """Human-readable summary label for a canonical vulnerability type."""
    return _kb_for(canonical)["label"]


__all__ = ["normalize_all", "enrich", "label_for", "cvss_severity", "severity_for_type"]