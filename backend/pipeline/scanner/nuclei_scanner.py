"""Nuclei scanner — template-based vulnerability scanning.

Runs `nuclei -u <target> -jsonl -silent` and parses JSONL output into
RawFinding objects. Nuclei tags (sqli, xss, lfi, rce, exposure, etc.) are
preserved on the finding so the normalizer can resolve the vulnerability type
and select an appropriate validator.

By default the scanner covers a BROAD tag scope (OWASP Top 10 classes plus
common misconfigurations) at HIGH concurrency so it produces generous
findings on real targets.

Requires nuclei to be installed. If nuclei is absent or a scan finds nothing,
an empty list is returned (never crashes the pipeline).
"""
from __future__ import annotations

import json
import subprocess
from typing import List, Optional

from app.models.scanner import RawFinding
from pipeline.scanner import base

# Broad default tag scope: valid nuclei category/tech tags only (invalid tags
# shrink the loaded template set in newer nuclei and can cause spurious
# no-template errors). Deduplicated, all lower-case.
BROAD_TAGS = (
    "cve,default-login,misconfig,exposure,config,cors,debug,"
    "dos,fuzz,tech,detect,file,headers,lfi,logging,misconfiguration,"
    "network,panel,race,redirect,scada,shell,sqli,xss,lfi,rce,ssrf,"
    "ssti,idor,oauth,graphql,websocket,health,backup,sensitive,cookie,"
    "env,actuator,springboot,apache,tomcat,nginx,php,wordpress,"
    "drupal,joomla,fastjson,log4j,s3,takeover,crypto,names,"
    "generic-detections,http,web,cloud,defaults,ssl,tls,certificate"
)

# Concurrency / rate-limit for generous findings.
CONCURRENCY = 100   # parallel threads
RATE_LIMIT = 250    # requests per second
TIMEOUT_SECS = 10   # per-request timeout

# Tags the normalizer can resolve into canonical vulnerability types.
SUPPORTED_TAGS = ("sqli", "xss", "lfi", "rce", "exposure", "info-disclosure",
                  "default-login", "csrf", "ssti", "idor", "ssrf",
                  "command-injection", "path-traversal", "xxe", "cve",
                  "open-redirect", "misconfiguration", "file-upload")


@base.register
class NucleiScanner(base.Scanner):
    name = "nuclei"
    executable = "nuclei"

    def scan(self, target: str, timeout: int = 300,
             include_tags: Optional[str] = None) -> List[RawFinding]:
        """Scan a target with nuclei -jsonl.

        Args:
            target: URL (e.g. http://127.0.0.1:8080).
            timeout: max execution time in seconds.
            include_tags: optional comma-separated nuclei tags to limit scope.
                If omitted, a BROAD tag scope (BROAD_TAGS) is used so the scan
                produces generous findings.

        Returns:
            List of RawFinding parsed from nuclei JSONL output. Never raises
            on empty results — returns [] if nothing matched.
        """
        nuclei_bin = self.resolved_path or "nuclei"
        cmd = [nuclei_bin, "-u", target, "-jsonl", "-silent"]
        cmd += ["-c", str(CONCURRENCY), "-rl", str(RATE_LIMIT),
                "-timeout", str(TIMEOUT_SECS),
                "-max-host-error", "10", "-severity", "low,medium,high,critical,unknown"]
        # Never fail the scan because nuclei wants an update or needs an
        # interactsh callback server for the template set in use.
        cmd += ["-disable-update-check", "-no-interactsh"]
        # Broad tag coverage by default; user-supplied tags narrow it.
        cmd += ["-tags", include_tags if include_tags else BROAD_TAGS]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            return []

        # A non-zero exit code does NOT mean zero findings: nuclei returns
        # non-zero for "no templates matched", template-compile warnings, or a
        # partially failed run even when it emitted valid JSONL. Parse whatever
        # was produced first; only fall back to [] when there is no output.
        findings = self._parse_output(proc.stdout, target)
        if findings:
            return findings
        if proc.returncode != 0:
            return []
        return findings

    def _parse_output(self, output: str, target: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = record.get("info", {}) or {}
            tags = self._extract_tags(info)

            vuln_type = self._resolve_type(tags)
            severity = (info.get("severity") or "low").lower()

            matched_at = record.get("matched-at")
            url = matched_at or record.get("url") or record.get("host") or target

            findings.append(
                RawFinding(
                    scanner="nuclei",
                    scanner_template_id=(record.get("template-id") or "nuclei-generic").lower(),
                    vulnerability_type=vuln_type,
                    target=record.get("host") or target,
                    host=(record.get("host") or target).replace("http://", "").replace("https://", ""),
                    service=None,
                    severity=severity,
                    url=url,
                    path=matched_at,
                    extraction=record.get("extractor-name") or record.get("extracted-results"),
                    matched_at=matched_at,
                    description=(info.get("description") or info.get("name") or ""),
                    raw={
                        "tags": tags,
                        "matcher_name": record.get("matcher-name"),
                        "template_id_raw": record.get("template-id"),
                    },
                )
            )
        return findings

    @staticmethod
    def _extract_tags(info: dict) -> list[str]:
        """Nuclei JSONL may emit 'tags' as a comma-separated string OR a
        JSON array. Normalize both to a flat, lowercase list of tags."""
        tags_raw = info.get("tags") or ""
        if isinstance(tags_raw, str):
            return [t.strip().lower() for t in tags_raw.split(",") if t.strip()]
        if isinstance(tags_raw, list):
            return [str(t).strip().lower() for t in tags_raw if str(t).strip()]
        return []

    @staticmethod
    def _resolve_type(tags: list[str]) -> Optional[str]:
        """Map a nuclei tag to a canonical vulnerability_type, or None."""
        tag_map = {
            "sqli": "sql_injection",
            "xss": "xss",
            "lfi": "lfi",
            "rce": "rce",
            "exposure": "exposure",
            "info-disclosure": "information_disclosure",
            "default-login": "default_login",
            "csrf": "csrf",
            "ssti": "ssti",
            "idor": "idor",
            "ssrf": "ssrf",
            "command-injection": "command_injection",
            "path-traversal": "path_traversal",
            "xxe": "xxe",
            "cve": "cve",
            "open-redirect": "open_redirect",
            "file-upload": "file_upload",
            "misconfiguration": "misconfiguration",
            "misconfig": "misconfiguration",
            "cors": "misconfiguration",
            "headers": "security_header",
            "security-misconfig": "misconfiguration",
            "cookie": "security_header",
            "debug": "information_disclosure",
            "health": "information_disclosure",
            "panel": "exposure",
            "backup": "information_disclosure",
            "sensitive": "information_disclosure",
            "subdomain-takeover": "subdomain_takeover",
            "takeover": "subdomain_takeover",
            "log4j": "rce",
            "fastjson": "rce",
            "springboot": "exposure",
            "actuator": "exposure",
            "env": "exposure",
            "config": "exposure",
            "cves": "cve",
            "defaultcve": "cve",
        }
        for tag in tags:
            if tag in tag_map:
                return tag_map[tag]
        return None
