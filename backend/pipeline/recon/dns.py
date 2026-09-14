"""DNS resolution — resolve target hostname to IP addresses."""
import socket
from typing import Optional

from app.models.recon import DnsResult


def resolve_a(host: str) -> Optional[str]:
    """Resolve a hostname to its primary IPv4 address, or None on failure."""
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def resolve_all(host: str) -> list[str]:
    """Resolve a hostname to all available IPv4 addresses."""
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET)
        ips = list({r[4][0] for r in results})
        return sorted(ips)
    except OSError:
        return []


def resolve(host: str) -> DnsResult:
    """Full DNS resolution for a hostname. Returns structured DnsResult."""
    host = host.strip()
    if not host:
        return DnsResult(hostname=host, resolution_status="error")

    if _looks_like_ip(host):
        return DnsResult(
            hostname=host,
            primary_ip=host,
            all_ips=[host],
            resolution_status="ip_passthrough",
        )

    primary = resolve_a(host)
    all_ips = resolve_all(host)

    if primary is None:
        return DnsResult(hostname=host, resolution_status="failed")

    return DnsResult(
        hostname=host,
        primary_ip=primary,
        all_ips=all_ips or [primary],
        resolution_status="resolved",
    )


def _looks_like_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False
