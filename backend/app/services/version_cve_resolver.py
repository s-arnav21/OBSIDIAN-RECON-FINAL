"""Version-to-CVE resolver with CVSS scoring.

Resolves detected software versions to known CVEs using the NIST NVD API
and local heuristic fallbacks. Provides per-CVE CVSS scoring for
exploitation prioritization.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_REQUEST_TIMEOUT = 10.0
_NVD_RATE_LIMIT_DELAY = 6.0
_NVD_PAGE_SIZE = 20

_CVE_SEVERITY_MAP = {
    "CRITICAL": 10.0,
    "HIGH": 8.5,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "NONE": 0.0,
}


@dataclass(frozen=True)
class CVEDetail:
    cve_id: str
    description: str
    cvss_v3_score: float
    cvss_v3_severity: str
    cvss_v3_vector: str
    published_date: str
    last_modified: str
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    @property
    def severity_label(self) -> str:
        if self.cvss_v3_score >= 9.0:
            return "critical"
        if self.cvss_v3_score >= 7.0:
            return "high"
        if self.cvss_v3_score >= 4.0:
            return "medium"
        return "low"

    @property
    def exploitation_priority(self) -> int:
        """Higher = should be exploited first."""
        return int(self.cvss_v3_score * 10)


@dataclass(frozen=True)
class VersionCVEMatch:
    product: str
    detected_version: str
    cves: List[CVEDetail]
    highest_cvss: float
    total_cves: int
    resolution_method: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "product": self.product,
            "detected_version": self.detected_version,
            "highest_cvss": self.highest_cvss,
            "total_cves": self.total_cves,
            "resolution_method": self.resolution_method,
            "cves": [
                {
                    "cve_id": c.cve_id,
                    "description": c.description,
                    "cvss_v3_score": c.cvss_v3_score,
                    "cvss_v3_severity": c.cvss_v3_severity,
                    "severity_label": c.severity_label,
                    "exploitation_priority": c.exploitation_priority,
                    "cwe_ids": c.cwe_ids,
                }
                for c in self.cves
            ],
        }


def _normalize_product_name(name: str) -> str:
    """Normalize product name for NVD query."""
    normalized = name.strip().lower()
    replacements = {
        "apache ": "",
        "nginx/": "nginx",
        "iis/": "iis",
        "php/": "php",
        "python/": "python",
        "node.js": "node",
        "nodejs": "node",
    }
    for old, new in replacements.items():
        if normalized.startswith(old):
            normalized = new or normalized[len(old):]
    return normalized.strip()


def _parse_version(version_str: str) -> tuple:
    """Parse version string into comparable tuple."""
    parts = re.split(r"[.\-_+]", version_str.strip())
    result = []
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            result.append(0)
    return tuple(result) if result else (0,)


def _version_matches(detected: str, vulnerable_range: str) -> bool:
    """Check if detected version falls within vulnerable range."""
    try:
        detected_parsed = _parse_version(detected)
        if "-" in vulnerable_range:
            start, end = vulnerable_range.split("-", 1)
            return _parse_version(start) <= detected_parsed <= _parse_version(end)
        if vulnerable_range.startswith(">="):
            return detected_parsed >= _parse_version(vulnerable_range[2:])
        if vulnerable_range.startswith("<"):
            return detected_parsed < _parse_version(vulnerable_range[1:])
        return _parse_version(vulnerable_range) == detected_parsed
    except Exception:
        return False


# Local CVE database for common products (fallback when NVD is unreachable)
_LOCAL_CVE_DATABASE: Dict[str, List[Dict[str, Any]]] = {
    "nginx": [
        {
            "cve_id": "CVE-2021-23017",
            "description": "Nginx DNS resolver vulnerability allows heap memory disclosure",
            "cvss_v3_score": 7.5,
            "cvss_v3_severity": "HIGH",
            "affected_versions": "<1.21.1",
            "cwe_ids": ["CWE-125"],
        },
        {
            "cve_id": "CVE-2022-41741",
            "description": "Nginx mp4 module memory corruption",
            "cvss_v3_score": 8.8,
            "cvss_v3_severity": "HIGH",
            "affected_versions": "<1.23.2",
            "cwe_ids": ["CWE-787"],
        },
    ],
    "apache": [
        {
            "cve_id": "CVE-2021-44790",
            "description": "Apache HTTP Server buffer overflow in mod_lua",
            "cvss_v3_score": 9.8,
            "cvss_v3_severity": "CRITICAL",
            "affected_versions": "<2.4.52",
            "cwe_ids": ["CWE-120"],
        },
        {
            "cve_id": "CVE-2022-22719",
            "description": "Apache HTTP Server mod_negotiation DoS",
            "cvss_v3_score": 7.5,
            "cvss_v3_severity": "HIGH",
            "affected_versions": "<2.4.53",
            "cwe_ids": ["CWE-400"],
        },
    ],
    "php": [
        {
            "cve_id": "CVE-2024-4577",
            "description": "PHP CGI argument injection vulnerability",
            "cvss_v3_score": 9.8,
            "cvss_v3_severity": "CRITICAL",
            "affected_versions": "<8.1.29",
            "cwe_ids": ["CWE-78"],
        },
        {
            "cve_id": "CVE-2024-2961",
            "description": "PHP iconv buffer overflow",
            "cvss_v3_score": 8.8,
            "cvss_v3_severity": "HIGH",
            "affected_versions": "<8.3.9",
            "cwe_ids": ["CWE-120"],
        },
    ],
    "mysql": [
        {
            "cve_id": "CVE-2023-21971",
            "description": "MySQL Server vulnerability affecting Server: DDL",
            "cvss_v3_score": 5.3,
            "cvss_v3_severity": "MEDIUM",
            "affected_versions": "<8.0.33",
            "cwe_ids": ["CWE-362"],
        },
    ],
    "postgresql": [
        {
            "cve_id": "CVE-2024-0567",
            "description": "PostgreSQL libpq connection leak",
            "cvss_v3_score": 5.3,
            "cvss_v3_severity": "MEDIUM",
            "affected_versions": "<16.1",
            "cwe_ids": ["CWE-404"],
        },
    ],
}


def _query_nvd_api(
    product: str,
    version: str,
    *,
    api_key: Optional[str] = None,
) -> List[CVEDetail]:
    """Query the NIST NVD API for CVEs matching a product and version."""
    api_key = api_key or os.getenv("NVD_API_KEY", "")
    headers = {"User-Agent": "ObsidianRecon/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    query = f"{product} {version}"
    params: Dict[str, Any] = {
        "keywordSearch": query,
        "resultsPerPage": _NVD_PAGE_SIZE,
    }

    try:
        client = httpx.Client(timeout=_NVD_REQUEST_TIMEOUT)
        response = client.get(_NVD_API_BASE, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        logger.warning("NVD API request failed for %s %s: %s", product, version, exc)
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        metrics = cve_data.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [{}])
        if not cvss_data:
            cvss_data = metrics.get("cvssMetricV30", [{}])
        cvss = cvss_data[0].get("cvssData", {}) if cvss_data else {}

        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        references = [
            ref.get("url", "")
            for ref in cve_data.get("references", [])
            if ref.get("url")
        ]

        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id.startswith("CWE-"):
                    cwe_ids.append(cwe_id)

        cves.append(CVEDetail(
            cve_id=cve_id,
            description=description,
            cvss_v3_score=cvss.get("baseScore", 0.0),
            cvss_v3_severity=cvss.get("baseSeverity", "UNKNOWN"),
            cvss_v3_vector=cvss.get("vectorString", ""),
            published_date=cve_data.get("published", ""),
            last_modified=cve_data.get("lastModified", ""),
            references=references[:10],
            cwe_ids=cwe_ids,
        ))

    return sorted(cves, key=lambda c: c.cvss_v3_score, reverse=True)


def _local_cve_lookup(
    product: str,
    version: str,
) -> List[CVEDetail]:
    """Look up CVEs from the local database."""
    normalized_product = _normalize_product_name(product)
    local_entries = _LOCAL_CVE_DATABASE.get(normalized_product, [])

    cves = []
    for entry in local_entries:
        if _version_matches(version, entry["affected_versions"]):
            cves.append(CVEDetail(
                cve_id=entry["cve_id"],
                description=entry["description"],
                cvss_v3_score=entry["cvss_v3_score"],
                cvss_v3_severity=entry["cvss_v3_severity"],
                cvss_v3_vector="",
                published_date="",
                last_modified="",
                references=[],
                cwe_ids=entry.get("cwe_ids", []),
            ))

    return sorted(cves, key=lambda c: c.cvss_v3_score, reverse=True)


def resolve_version_to_cves(
    product: str,
    version: str,
    *,
    use_nvd_api: bool = True,
    api_key: Optional[str] = None,
) -> VersionCVEMatch:
    """Resolve a detected software version to known CVEs.

    Tries the NVD API first (when enabled), falls back to local database.
    """
    cves: List[CVEDetail] = []
    method = "local_database"

    if use_nvd_api:
        cves = _query_nvd_api(product, version, api_key=api_key)
        if cves:
            method = "nvd_api"
        time.sleep(_NVD_RATE_LIMIT_DELAY)

    if not cves:
        cves = _local_cve_lookup(product, version)
        method = "local_database" if cves else "no_matches"

    highest_cvss = max((c.cvss_v3_score for c in cves), default=0.0)

    return VersionCVEMatch(
        product=product,
        detected_version=version,
        cves=cves,
        highest_cvss=highest_cvss,
        total_cves=len(cves),
        resolution_method=method,
    )


def batch_resolve_versions(
    services: List[Dict[str, str]],
    *,
    use_nvd_api: bool = True,
    api_key: Optional[str] = None,
) -> List[VersionCVEMatch]:
    """Resolve multiple product/version pairs to CVEs."""
    results = []
    for service in services:
        product = service.get("product", "")
        version = service.get("version", "")
        if product and version:
            result = resolve_version_to_cves(
                product, version,
                use_nvd_api=use_nvd_api,
                api_key=api_key,
            )
            results.append(result)
    return results
