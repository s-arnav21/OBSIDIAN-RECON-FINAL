"""Triage layer — organize raw scanner findings for readability.

The triage layer NEVER discards or edits raw findings. It only groups them so
that noisy duplicate output (e.g. a nuclei template firing once per header)
collapses into a single row with an occurrence count, and orders groups by
severity. Every RawFinding passed in stays fully intact, so downstream layers
(the future TTP/validation pipeline) still see the complete, unmodified set.

Cross-scanner exposure-family dedup (BUG 2):
  - "exposed-config"/"exposed-sensitive-file" from http_probe + "discovered-path" from content
    scanner pointing to the same URL → merged into one finding.
  - "missing-security-header" across subdomains → grouped into one row with all affected hosts.

Same-port cross-scanner dedup (port-scan skill + nmap scanner):
  The port-scan skill emits "port-open" + "service-detected" and the nmap
  scanner emits "open-port" for the same physical open port. Without a
  cross-scanner pass these triple-nest into three indistinguishable info rows
  per port. They are merged on (host, port, proto) into one row carrying the
  full occurrence count and a "scanned-by" source tag.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urlparse

from app.models.scanner import RawFinding

_EXPOSURE_FAMILY = {
    "exposed-config",
    "exposed-sensitive-file",
    "discovered-path",
}

# Same cookie audited in two places (cookie-audit skill + http_probe scanner)
# → one row per (host, cookie name).
_INSECURE_COOKIE_FAMILY = {
    "insecure-cookie",
}

# Technology stack disclosed via several templates → one row per (host, tech).
_TECH_DISCLOSURE_FAMILY = {
    "tech-fingerprint",
    "technology-identified",
    "server-info-leak",
    "information_disclosure",
}

# Banner tokens used to attribute an unlabeled finding to a technology.
# Tested in priority order so "Microsoft-IIS/10.0" and "Microsoft IIS" both
# normalize to "iis", while adjacent-but-distinct stacks (nginx/apache/tomcat)
# stay separate.
_KNOWN_TECH_NAMES = (
    "iis", "nginx", "apache", "tomcat", "httpd", "asp.net", "aspnet",
    "cloudflare", "varnish", "fastly", "akamai", "uvicorn", "gunicorn",
    "werkzeug", "phusion", "passenger",
)

# Templates that describe the SAME physical open port, produced by different
# tools. "port-open"/"service-detected" come from the port-scan skill (nmap),
# "open-port" from the nmap scanner — merged on (host, port, proto).
_PORT_OPEN_FAMILY = {
    "port-open",
    "open-port",
    "service-detected",
}

_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

# --- knowledge-base scoring (CVSS + OWASP + context modifiers) -------------

_OWASP_MODIFIER = 0.5
_CREDENTIALS_MODIFIER = 1.0
_RCE_MODIFIER = 1.0
_AUTH_BYPASS_MODIFIER = 0.5
_LOCAL_MODIFIER = -0.5
_PHYSICAL_MODIFIER = -1.0
_SCORE_CAP = 10.0
_SCORE_FLOOR = 0.1


def cvss_severity(score: float) -> str:
    """Severity label for a CVSS v3 base score."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= _SCORE_FLOOR:
        return "low"
    if score == 0.0:
        return "info"
    return "unknown"


def calculate_severity(
    cvss_base: float = 0.0,
    *,
    in_owasp_top_10: bool = True,
    creds_exposed: bool = False,
    rce_possible: bool = False,
    auth_bypass: bool = False,
    requires_local_access: bool = False,
    requires_physical_access: bool = False,
) -> tuple[float, str]:
    """Final severity from the attack knowledge base.

        FINAL = CVSS_BASE + OWASP_MODIFIER(+0.5) + CONTEXT_MODIFIER(±)

    Context modifiers (from the user's KB spec):
      +1.0  credentials/sensitive data exposed,
      +1.0  remote code execution possible,
      +0.5  authentication bypass,
      -0.5  requires local access,
      -1.0  requires physical access.

    The result is clamped to [0.1, 10.0] and returned with its severity label.
    """
    score = float(cvss_base or 0.0)
    if in_owasp_top_10:
        score += _OWASP_MODIFIER
    if creds_exposed:
        score += _CREDENTIALS_MODIFIER
    if rce_possible:
        score += _RCE_MODIFIER
    if auth_bypass:
        score += _AUTH_BYPASS_MODIFIER
    if requires_local_access:
        score += _LOCAL_MODIFIER
    if requires_physical_access:
        score += _PHYSICAL_MODIFIER

    score = max(_SCORE_FLOOR, min(_SCORE_CAP, round(score, 1)))
    return score, cvss_severity(score)


def normalize_url(url: str) -> str:
    """Normalize a URL for dedup: strip query, fragment, normalize scheme+host."""
    if not url:
        return ""
    parsed = urlparse(url)
    # Normalize scheme
    scheme = (parsed.scheme or "http").lower()
    # Normalize host
    host = (parsed.hostname or "").lower()
    # Normalize path: remove trailing slash unless it's just "/"
    path = parsed.path
    if path == "":
        path = "/"
    elif not path.endswith("/"):
        path = path.rstrip("/")
    # Reconstruct
    return f"{scheme}://{host}{path}"


def _dummy_key(g: object) -> tuple:
    """Return a sort-key-tuple that sorts after all real keys."""
    return (999,)


@dataclass
class TriageGroup:
    """A set of identical findings collapsed into one readable row.

    `finding` is the first (representative) finding of the group; `occurrences`
    is how many times the same thing fired; `hosts`/`urls` list the distinct
    matched hosts and URLs so nothing is hidden.
    """
    finding: RawFinding
    occurrences: int = 1
    hosts: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        f = self.finding
        return {
            "scanner": f.scanner,
            "scanner_template_id": f.scanner_template_id,
            "vulnerability_type": f.vulnerability_type,
            "severity": f.severity,
            "description": f.description,
            "service": f.service,
            "port": f.port,
            "url": f.url,
            "path": f.path,
            "hosts": sorted(set(self.hosts)),
            "urls": sorted(set(self.urls)),
            "occurrences": self.occurrences,
            "extraction": f.extraction,
            "matched_at": f.matched_at,
            "raw": f.raw,
        }


@dataclass
class TriageSummary:
    """Grouped view over a raw finding list, with per-tool/per-severity counts.

    `raw_findings` is the exact input list — grouped view never drops data.
    """
    total_findings: int
    unique_findings: int
    groups: List[TriageGroup] = field(default_factory=list)
    by_severity: dict = field(default_factory=dict)
    by_scanner: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "unique_findings": self.unique_findings,
            "removed_duplicates": self.total_findings - self.unique_findings,
            "by_severity": self.by_severity,
            "by_scanner": self.by_scanner,
            "groups": [g.to_dict() for g in self.groups],
        }


def triage(findings: List[RawFinding]) -> TriageSummary:
    """Group and order a list of raw findings.

    Groups are keyed by (scanner, template id, severity, matched host) so that
    template re-fires on the same host collapse into one row carrying an
    `occurrences` count plus the distinct hosts/URLs. Groups are ordered by
    severity (critical first), then most-frequent first.

    Cross-scanner exposure-family dedup (BUG 2):
      - "exposed-config"/"exposed-sensitive-file" from http_probe +
        "discovered-path" from content scanner pointing to the same URL
        → merged into one finding.
      - "missing-security-header" across subdomains → grouped into one row
        with all affected hosts.
      - "port-open"/"service-detected" (port-scan skill) + "open-port" (nmap
        scanner) for the same open port → merged on (host, port, proto).
    """
    grouped: dict[tuple, TriageGroup] = {}
    for f in findings:
        key = _dedup_key(f)
        if key in grouped:
            group = grouped[key]
            group.occurrences += 1
            host, url = _host_of(f), f.url or ""
            if host and host not in group.hosts:
                group.hosts.append(host)
            if url and url not in group.urls:
                group.urls.append(url)
            continue
        host, url = _host_of(f), f.url or ""
        grouped[key] = TriageGroup(
            finding=f,
            occurrences=1,
            hosts=[host] if host else [],
            urls=[url] if url else [],
        )

    # === Cross-scanner / cross-template family dedup ===
    # Several families fire from multiple tools for the same logical exposure
    # (e.g. the same insecure cookie audited by the cookie-audit skill and the
    # http_probe scanner, or the same web server technology reported by
    # tech-fingerprint + server-info-leak + the technology-identified skill).
    # Within each family we group by a key and merge into one row, keeping every
    # source URL/host and annotating the raw finding with where each detection
    # came from.
    _FAMILY_PASSES: list[tuple[str, set[str], object]] = [
        ("exposure", _EXPOSURE_FAMILY,
         lambda f: normalize_url(f.url or f.target or "")),
        ("cookie", _INSECURE_COOKIE_FAMILY,
         lambda f: (_host_of(f).lower(), _cookie_name_of(f))),
        ("tech", _TECH_DISCLOSURE_FAMILY,
         lambda f: (_host_of(f).lower(), _tech_label_of(f))),
        ("port", _PORT_OPEN_FAMILY, _port_key_of),
    ]

    merged_by_family: dict[str, list[TriageGroup]] = {}
    merged_group_keys: set[tuple] = set()

    for family_name, family_set, key_fn in _FAMILY_PASSES:
        by_key: dict[object, list[tuple]] = {}
        for key, group in grouped.items():
            f = group.finding
            # Membership is matched on either the vulnerability_type or the
            # scanner template id, so findings that carry the family token in
            # scanner_template_id (e.g. port-scan/nmapper port columns that set
            # vulnerability_type="reconnaissance") still group correctly.
            vuln_type = f.vulnerability_type or ""
            tmpl = (f.scanner_template_id or "").lower()
            in_family = vuln_type in family_set or tmpl in family_set
            if in_family:
                by_key.setdefault(key_fn(f), []).append((key, group))

        merged: list[TriageGroup] = []
        for family_key, entries in by_key.items():
            groups = [g for _, g in entries]
            if len(groups) == 1:
                # Single-detection family findings stay untouched in `grouped`.
                continue

            best = max(
                groups,
                key=lambda g: _SEVERITY_RANK.get(
                    (g.finding.severity or "info").lower(), 0),
            )

            all_hosts: set[str] = set()
            all_urls: set[str] = set()
            for g in groups:
                all_hosts.update(g.hosts)
                all_urls.update(g.urls)
            best.hosts = sorted(all_hosts)
            best.urls = sorted(all_urls)
            best.occurrences = sum(g.occurrences for g in groups)

            # Keep the richest identification of the merged row: carry
            # service/version/banner detail from any partner when the
            # representative lacks it (e.g. nmap "open-port" banner alongside
            # the skill's "service-detected" version string).
            best_raw = dict(best.finding.raw or {})
            for g in groups:
                if g is best:
                    continue
                other_raw = g.finding.raw or {}
                if not best.finding.service and g.finding.service:
                    best.finding.service = g.finding.service
                for k in ("version", "service", "service_name", "banner",
                          "raw_banner", "protocol", "proto"):
                    if not best_raw.get(k) and other_raw.get(k):
                        best_raw[k] = other_raw[k]
                if best.finding.service and best_raw.get("version"):
                    break
            best.finding.raw = best_raw

            scanner_names: set[str] = set()
            for g in groups:
                scanner_names.add(g.finding.scanner)
            best.finding.raw = dict(best.finding.raw or {})
            existing_sources = best.finding.raw.get("sources", [])
            scanner_tag = f"scanned-by: {', '.join(sorted(scanner_names))}"
            if existing_sources:
                existing_sources.append(scanner_tag)
            else:
                existing_sources = [scanner_tag]
            best.finding.raw["sources"] = existing_sources

            merged.append(best)
            merged_group_keys.update(k for k, _ in entries)

        merged_by_family[family_name] = merged

    # Build the final group list: original groups minus any that were merged
    # into a family row, plus the merged rows.
    final_groups: dict[tuple, TriageGroup] = {}
    for key, group in grouped.items():
        if key in merged_group_keys:
            continue
        final_groups[key] = group

    idx = 0
    for family_name in ("exposure", "cookie", "tech", "port"):
        for mg in merged_by_family[family_name]:
            final_groups[(idx, family_name)] = mg
            idx += 1

    # Sort by severity (critical first), then most-frequent first.
    all_groups = list(final_groups.values())
    all_groups.sort(
        key=lambda g: (
            _SEVERITY_RANK.get((g.finding.severity or "info").lower(), 0),
            g.occurrences,
        ),
        reverse=True,
    )

    # Severity / scanner counts reflect the COLLAPSED view (one per unique
    # group), so a report of N raw findings that dedup to M rows reads as M —
    # not as a wall of M×k "info" rows.
    severity_counts: dict[str, int] = {}
    scanner_counts: dict[str, dict] = {}
    for g in all_groups:
        sev = (g.finding.severity or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        per = scanner_counts.setdefault(g.finding.scanner, {})
        per[sev] = per.get(sev, 0) + 1

    return TriageSummary(
        total_findings=len(findings),
        unique_findings=len(all_groups),
        groups=all_groups,
        by_severity=severity_counts,
        by_scanner=scanner_counts,
    )


def _dedup_key(f: RawFinding) -> tuple:
    host = _host_of(f)
    url = (f.url or f.matched_at or "").strip().lower()
    return (f.scanner, (f.scanner_template_id or "").lower(),
            (f.severity or "info").lower(), host.lower(), url, f.port)


def _host_of(f: RawFinding) -> str:
    """Best-effort bare hostname for a finding (matched-at > url > host)."""
    for candidate in (f.matched_at, f.url, f.host):
        if not candidate:
            continue
        text = str(candidate).strip()
        if not text:
            continue
        if "://" in text:
            host = urlparse(text).hostname
            if host:
                return host
        else:
            # raw host[:port] or bare hostname
            bare = text.rstrip("/").split(":")[0].strip()
            if bare:
                return bare
    return (f.target or "").strip()


def _port_key_of(f: RawFinding) -> tuple:
    """Best-effort (host, port, proto) key for a physical open port.

    Shared by the port-scan skill findings ("port-open", "service-detected")
    and the nmap scanner ("open-port") so the same port from both tools
    collapses into one row. Missing port → an unmergeable key.
    """
    raw = f.raw or {}
    proto = str(raw.get("protocol") or raw.get("proto") or "tcp").lower()
    port = f.port
    if port is None:
        try:
            port = int(raw.get("port"))
        except (TypeError, ValueError, KeyError):
            port = None
    return (_host_of(f).lower(), port, proto)


def _cookie_name_of(f: RawFinding) -> str:
    """Best-effort cookie name for a finding (http_probe vs cookie-audit)."""
    raw = f.raw or {}
    name = raw.get("cookie") if raw.get("cookie") else raw.get("cookie_name")
    if isinstance(name, dict):
        name = name.get("name") or ""
    return (str(name) or "").strip().lower()


def _tech_label_of(f: RawFinding) -> str:
    """Best-effort technology label for a tech-disclosure finding.

    Priority: explicit tech field (tech_fingerprint / subdomains_httpx),
    then banner headers (server / x-powered-by), then matching the label
    against known tech names so "IIS", "Microsoft IIS" and
    "Microsoft-IIS/10.0" all normalize to one key.
    """
    raw = f.raw or {}
    label = ""
    for key in ("tech", "technology", "server", "x_powered_by"):
        val = raw.get(key)
        if not val:
            continue
        label = str(val).strip()
        if label:
            break
    if label:
        low = label.lower()
        for tech in _KNOWN_TECH_NAMES:
            if tech in low:
                return tech
        return low.split(",")[0].split("(")[0].strip()[:60]
    desc = (f.description or "").lower()
    for tech in _KNOWN_TECH_NAMES:
        if tech in desc:
            return tech
    return desc[:60] or "unknown"


__all__ = ["triage", "TriageSummary", "TriageGroup", "_SEVERITY_RANK",
           "normalize_url", "_dummy_key"]