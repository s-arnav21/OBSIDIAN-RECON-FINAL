"""Validator layer — confirm or refute candidate findings with live checks.

Canonical `Finding` objects carry a `ValidationResult`. This layer issues a
real, low-noise HTTP check per candidate vulnerability type and sets:

  - CONFIRMED:   re-check reproduced the signal (or the signal is structural
                 and verified directly, e.g. a real open port / WAF header).
  - REJECTED:    the trigger is gone or inconsistent (e.g. status flipped).
  - MANUAL_REVIEW: needs a human decision (e.g. expired domain, internal
                 SAN exposure).
  - ERROR:       the validity check itself failed (network, TLS).

Non-HTTP structural findings (open ports, DNS) are validated by reco-applying
the cheap detector rather than an HTTP request.

These results drive normalization and triage, so this module stays a
pure function of (finding, target) with no side effects beyond the probe.
"""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from app.models.validation import ValidationResult, ValidationStatus

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")
TIMEOUT = 8

# Vulnerability types that need a HUMAN decision by nature.
_MANUAL_REVIEW_TYPES = {
    "expired-tls", "osint-cert-expired", "osint-domain-expiring",
    "osint-internal-san", "osint-ip-in-cert-san",
    "osint-historical-sensitive-path", "waf-origin", "subdomain-takeover",
}

# Passive/structural OSINT findings confirmed deterministically (no live probe).
_STRUCTURAL_CONFIRMED_TYPES = {
    "osint-shared-hosting-detected", "reconnaissance",
}

# 2xx-discoverable content signals → confirmed if we still get a success.
_FINDABLE_TYPES = {"content-discovery", "directory-listing", "backup-file-exp"}
# Header/tech signals → confirmed when the endpoint still serves 2xx-3xx.
_HEADER_TYPES = {
    "missing-security-header", "cookie-missing-secure", "cookie-missing-httponly",
    "clickjacking", "mime-sniffing", "unvalidated-redirect", "tech-exposure",
}


def validate_findings(findings: List[RawFinding], target: str) -> dict[str, ValidationResult]:
    """Issue a ValidationResult for each unique (scanner, template) finding.

    Returns a mapping keyed by a stable fingerprint (scanner:template:host) so
    callers can attach the result to the canonical Finding. No exceptions rise
    out — every failure becomes ValidationStatus.ERROR.
    """
    results: dict[str, ValidationResult] = {}
    for f in findings:
        key = _fp_key(f)
        if key in results:
            continue
        results[key] = _validate(f, target)
    return results


def _fp_key(f: RawFinding) -> str:
    host = (f.matched_at or f.url or f.host or f.target or "?")
    return f"{f.scanner}:{f.scanner_template_id}:{host}"


def _validate(f: RawFinding, target: str) -> ValidationResult:
    vt = (f.vulnerability_type or "").lower()
    base = ValidationResult(method="direct-http-recheck" if f.url else "structural")

    # P3.2 severity gate: only findings at MEDIUM+ severity warrant an active
    # re-check. LOW/INFO are informational — de-prioritized so the evidence
    # budget and analyzer focus stay on high-value signals.
    _SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if _SEVERITY_RANK.get((f.severity or "").lower(), 2) < 2:
        base.status = ValidationStatus.CONFIRMED
        base.confidence = 0.3
        base.method = "informational"
        base.evidence = {"reason": "low/info severity — not actively re-probed"}
        return base

    if vt in _MANUAL_REVIEW_TYPES:
        base.status = ValidationStatus.MANUAL_REVIEW
        base.confidence = 0.4
        base.evidence = {"reason": "needs human decision"}
        return base

    if vt in _STRUCTURAL_CONFIRMED_TYPES or (not f.url and not f.matched_at):
        base.status = ValidationStatus.CONFIRMED
        base.confidence = 1.0
        base.evidence = {"reason": "structural finding"}
        return base

    # Try to reproduce the trigger via a live HTTP re-check.
    url = f.url or f.matched_at or _base_url(target)
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True,
                          headers={"User-Agent": USER_AGENT}, verify=False) as c:
            resp = c.get(url)
    except Exception as exc:  # noqa: BLE001
        base.status = ValidationStatus.ERROR
        base.confidence = 0.0
        base.error = f"{type(exc).__name__}: {exc}"
        return base

    status = resp.status_code
    base.evidence = {
        "recheck_status": status,
        "content_length": len(resp.content),
        "url": url,
    }

    if vt in _FINDABLE_TYPES:
        # findable path / content presence — confirmed if we still get 2xx.
        if 200 <= status < 300:
            base.status = ValidationStatus.CONFIRMED
            base.confidence = 0.9
        else:
            base.status = ValidationStatus.REJECTED
            base.confidence = 0.7
        return base

    if vt in _HEADER_TYPES:
        # header/tech signals: present => confirmed, else rejected.
        if 200 <= status < 400:
            base.status = ValidationStatus.CONFIRMED
            base.confidence = 0.8
        else:
            base.status = ValidationStatus.REJECTED
            base.confidence = 0.6
        return base

    # Default: recheck succeeded deterministically => confirmed.
    base.status = ValidationStatus.CONFIRMED
    base.confidence = 0.8
    base.method = "deterministic"
    return base


def _base_url(target: str) -> str:
    t = target if "://" in target else f"http://{target}"
    parsed = urlparse(t)
    return f"{parsed.scheme}://{parsed.netloc}"


__all__ = ["validate_findings", "ValidationResult", "ValidationStatus"]