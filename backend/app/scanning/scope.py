"""Explicit authorization and exact-origin controls for reconnaissance."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

from app.scanning.dns import BoundedDnsResolver, DnsLookupError
from app.core.config import settings


class ReconAuthorizationError(ValueError):
    pass


class ReconScopeError(ValueError):
    pass


class TargetVerificationRequiredError(ReconScopeError):
    def __init__(self, target: "AuthorizedTarget") -> None:
        super().__init__(
            "DNS ownership verification is required for this external target"
        )
        self.target = target


@dataclass(frozen=True)
class AuthorizedTarget:
    origin: str
    hostname: str
    port: int
    scheme: str
    resolved_addresses: tuple[str, ...] = ()


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def is_loopback_host(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _canonical_hostname(hostname: str) -> str:
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    value = hostname.rstrip(".")
    try:
        ascii_hostname = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ReconScopeError("target_url contains an invalid hostname") from exc
    labels = ascii_hostname.split(".")
    if (
        not ascii_hostname
        or len(ascii_hostname) > 253
        or any(not _DNS_LABEL.fullmatch(label) for label in labels)
    ):
        raise ReconScopeError("target_url contains an invalid hostname")
    return ascii_hostname


def normalize_origin(value: str) -> AuthorizedTarget:
    if not isinstance(value, str) or not value.strip():
        raise ReconScopeError("target_url must be a non-empty URL")
    try:
        parsed = urlsplit(value.strip())
        explicit_port = parsed.port
    except ValueError as exc:
        raise ReconScopeError("target_url contains an invalid port") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ReconScopeError("target_url must be an HTTP origin")
    if parsed.username is not None or parsed.password is not None:
        raise ReconScopeError("target_url must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ReconScopeError("target_url must be an origin without path or query")

    hostname = _canonical_hostname(parsed.hostname.lower())
    port = explicit_port or (443 if scheme == "https" else 80)
    default_port = 443 if scheme == "https" else 80
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = display_host if port == default_port else f"{display_host}:{port}"
    return AuthorizedTarget(
        origin=urlunsplit((scheme, netloc, "", "", "")),
        hostname=hostname,
        port=port,
        scheme=scheme,
    )


def validate_public_addresses(addresses: Sequence[str]) -> tuple[str, ...]:
    if not addresses:
        raise ReconScopeError("verified target hostname did not resolve")
    normalized = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ReconScopeError(
                "verified target returned an invalid network address"
            ) from exc
        if (
            not address.is_global
            or address.is_loopback
            or address.is_private
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ReconScopeError(
                "verified target resolves to a non-public network address"
            )
        normalized.append(str(address))
    return tuple(dict.fromkeys(normalized))


def resolve_public_target_addresses(
    hostname: str,
    *,
    address_resolver: Optional[Callable[[str], Sequence[str]]] = None,
) -> tuple[str, ...]:
    resolver = address_resolver or BoundedDnsResolver().resolve_addresses
    try:
        addresses = resolver(hostname)
    except DnsLookupError as exc:
        raise ReconScopeError(
            "verified target address resolution failed"
        ) from exc
    return validate_public_addresses(tuple(addresses))


def authorize_target(
    target_url: str,
    *,
    authorized: bool,
    ownership_verified: bool = False,
    address_resolver: Optional[Callable[[str], Sequence[str]]] = None,
) -> AuthorizedTarget:
    if authorized is not True:
        raise ReconAuthorizationError(
            "explicit authorization confirmation is required"
        )
    target = normalize_origin(target_url)
    if is_loopback_host(target.hostname):
        return target
    if not settings.AUTHORIZATION_RESTRICTED:
        # Explicit operator opt-out (parity with the legacy pipeline's
        # AUTHORIZATION_RESTRICTED=false): no HTTPS requirement, no DNS
        # ownership verification, no public-address enforcement. The operator
        # confirmation above is the gate.
        return target
    if target.scheme != "https":
        raise ReconScopeError(
            "external reconnaissance targets must use HTTPS"
        )
    if not ownership_verified:
        raise TargetVerificationRequiredError(target)
    addresses = resolve_public_target_addresses(
        target.hostname,
        address_resolver=address_resolver,
    )
    return AuthorizedTarget(
        origin=target.origin,
        hostname=target.hostname,
        port=target.port,
        scheme=target.scheme,
        resolved_addresses=addresses,
    )
