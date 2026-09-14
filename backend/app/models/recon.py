"""Recon pipeline data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class DnsResult:
    hostname: str
    primary_ip: Optional[str] = None
    all_ips: list[str] = field(default_factory=list)
    resolution_status: str = "pending"

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "primary_ip": self.primary_ip,
            "all_ips": self.all_ips,
            "resolution_status": self.resolution_status,
        }


@dataclass
class LiveHostResult:
    url: str
    host: str
    ip: Optional[str] = None
    status_code: Optional[int] = None
    headers: dict = field(default_factory=dict)
    body_sample: str = ""
    https_supported: bool = True
    response_time_ms: Optional[int] = None
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    reachable: bool = False

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "ip": self.ip,
            "status_code": self.status_code,
            "headers": self.headers,
            "body_sample": self.body_sample[:500],
            "https_supported": self.https_supported,
            "response_time_ms": self.response_time_ms,
            "server": self.server,
            "x_powered_by": self.x_powered_by,
            "reachable": self.reachable,
        }


@dataclass
class FingerprintResult:
    technologies: list[str] = field(default_factory=list)
    categories: dict = field(default_factory=dict)
    raw_matches: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technologies": self.technologies,
            "categories": self.categories,
            "raw_matches": self.raw_matches,
        }


@dataclass
class Asset:
    url: str
    host: str
    ip: Optional[str] = None
    status_code: Optional[int] = None
    technologies: list[str] = field(default_factory=list)
    https_supported: bool = True
    role: str = "web"
    is_primary: bool = False
    osint: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "ip": self.ip,
            "status_code": self.status_code,
            "technologies": self.technologies,
            "https_supported": self.https_supported,
            "role": self.role,
            "is_primary": self.is_primary,
            "osint": self.osint,
        }


@dataclass
class ReconResult:
    target: str
    dns: Optional[DnsResult] = None
    live: Optional[LiveHostResult] = None
    fingerprint: Optional[FingerprintResult] = None
    assets: list[Asset] = field(default_factory=list)
    primary_asset: Optional[Asset] = None
    osint_findings: list[dict] = field(default_factory=list)  # RawFinding.to_dict()
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total_assets: int = 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "dns": self.dns.to_dict() if self.dns else None,
            "live": self.live.to_dict() if self.live else None,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "assets": [a.to_dict() for a in self.assets],
            "primary_asset": self.primary_asset.to_dict() if self.primary_asset else None,
            "osint_findings": self.osint_findings,
            "total_assets": self.total_assets,
            "timestamp": self.timestamp,
        }
