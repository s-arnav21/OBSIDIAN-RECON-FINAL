"""Deterministic post-discovery correlation over all raw findings.

Always runs (requires_all: []). Consumes the accumulated `ctx.raw_findings`
and emits one `correlation-chain` finding per satisfied rule. A rule fires
when every finding type in `trigger_types` is present; the reported severity
is the highest severity among its constituents.

Rules are pure functions of the finding set so the same input always produces
the same chains — fully deterministic, no external reasoning layer.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_PRINTABLE_NAMES = {
    "default-credentials-valid": "web default credentials",
    "ssh-default-creds": "SSH default credentials",
    "mysql-default-creds": "MySQL default credentials",
    "ftp-anonymous-login": "anonymous FTP",
    "ftp-backdoor": "ProFTPD 1.3.3c backdoor (CVE-2010-4221)",
    "snmp-default-community": "default SNMP community",
    "smb-null-session": "SMB null session",
    "rce-signal": "RCE signal",
    "lfi-confirmed": "local file inclusion",
    "xxe-confirmed": "XXE",
    "sqli-error-signal": "error SQL injection",
    "high_finding_exists": "high/critical finding",
    "wp-xmlrpc-enabled": "WordPress XML-RPC exposed",
    "wp-user-enum": "WordPress user enumeration",
}

_RULES: List[Tuple[str, Tuple[str, ...]]] = [
    ("default-credential-chain",
     ("default-credentials-valid", "ssh-default-creds", "mysql-default-creds",
      "ftp-anonymous-login", "snmp-default-community", "smb-null-session")),
    ("rce-chain", ("rce-signal",)),
    ("data-read-chain", ("lfi-confirmed", "xxe-confirmed",
                         "sqli-error-signal")),
    ("credential-and-exposed-admin",
     ("default-credentials-valid", "admin-interface-exposed")),
    # VM-1: the ProFTPD 1.3.3c build IS the root shell — a single finding,
    # surfaced as a chain so the report's correlation layer names it.
    ("proftpd-backdoor-root-shell", ("ftp-backdoor",)),
]

_DEFAULT_CHAIN_RULES: List[Tuple[str, str, str]] = [
    ("credential-and-exposed-admin",
     "admin-interface-exposed", "default-credentials-valid"),
    # VM-2: known-valid default creds against a WordPress install that also
    # exposes XML-RPC => authenticated plugin-upload/credential-guess RCE.
    ("wordpress-credential-rce",
     "wp-xmlrpc-enabled", "default-credentials-valid"),
    # VM-2 alternate: enumerated WordPress users + exposed XML-RPC => the
    # system accounts are known for a targeted credential attack.
    ("wordpress-user-enum-rce",
     "wp-user-enum", "wp-xmlrpc-enabled"),
]


def _best_severity(fs: List[RawFinding]) -> str:
    sev = max((x.severity for x in fs if x.severity in _SEVERITY_RANK),
              default="info", key=lambda s: _SEVERITY_RANK[s])
    return sev


def _names(ids: set[str]) -> List[str]:
    return [_PRINTABLE_NAMES.get(i, i) for i in sorted(ids)]


@register
class CorrelateSkill(Skill):
    """Correlate accumulated findings into exploit chains."""

    name = "correlate"
    display_name = "Finding correlation"
    category = SkillCategory.POST
    version = "1.0"
    requires_all: list[str] = []
    requires_any: list[str] = []

    timeout_seconds = 10
    max_requests = 0

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(ctx.raw_findings)

    def run(self, ctx: SkillContext) -> SkillResult:
        findings = list(ctx.raw_findings)
        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"correlation_chains": []}})

        present = {f.scanner_template_id for f in findings}
        chains: List[Dict] = []

        # group rules (or-style; >=1 of listed types needed)
        for chain_id, types in _RULES:
            present_now = present & set(types)
            if not present_now:
                continue
            involved = [f for f in findings
                        if f.scanner_template_id in present_now]
            chains.append({"chain_id": chain_id,
                           "severity": _best_severity(involved),
                           "types": sorted(present_now),
                           "labels": _names(present_now)})

        # pair rules (both required)
        for chain_id, a, b in _DEFAULT_CHAIN_RULES:
            if a in present and b in present:
                involved = [f for f in findings
                            if f.scanner_template_id in (a, b)]
                chains.append({"chain_id": chain_id,
                               "severity": _best_severity(involved),
                               "types": sorted({a, b}),
                               "labels": _names({a, b})})

        # cap output
        chains = chains[: 8]
        if not chains:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"correlation_chains": []}})

        converted: List[RawFinding] = []
        for c in chains:
            converted.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="correlation-chain",
                vulnerability_type="correlation",
                target=ctx.target_url, host=ctx.host,
                severity=c["severity"],
                url=ctx.target_url,
                description=(f"Correlation chain '{c['chain_id']}': "
                             f"{', '.join(c['labels'])}"),
                raw=c,
            ))
        return SkillResult(
            skill_name=self.name, success=True, findings=converted,
            context_updates={"osint": {
                "correlation_chains": [c["chain_id"] for c in chains]}})